package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"opentunnel/internal/serverpool"
)

// Enrollment accounts grant no administrator session and no traffic admission.
// Disabling an account prevents new enrollment; existing devices still require
// explicit peer revocation/ban if the operator wants to disconnect them.
func (h *Handler) enrollmentAccountsAPI(w http.ResponseWriter, r *http.Request) {
	if h.poolID == "" {
		http.Error(w, "configure a trusted server pool before managing enrollment accounts", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		rows, err := h.db.QueryContext(r.Context(), `SELECT a.username,a.enabled,a.max_devices,(SELECT COUNT(*) FROM peer_enrollments e JOIN peers p ON p.token=e.token WHERE e.username=a.username) FROM enrollment_accounts a ORDER BY username LIMIT 256`)
		if err != nil {
			http.Error(w, "enrollment account inventory unavailable", 503)
			return
		}
		defer rows.Close()
		type account struct {
			Username   string `json:"username"`
			Enabled    bool   `json:"enabled"`
			MaxDevices int    `json:"max_devices"`
			Devices    int    `json:"devices"`
		}
		accounts := []account{}
		for rows.Next() {
			var a account
			if err := rows.Scan(&a.Username, &a.Enabled, &a.MaxDevices, &a.Devices); err != nil {
				http.Error(w, "enrollment account inventory unavailable", 503)
				return
			}
			accounts = append(accounts, a)
		}
		if rows.Err() != nil {
			http.Error(w, "enrollment account inventory unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			LoginRequired bool      `json:"login_required"`
			Accounts      []account `json:"accounts"`
		}{h.enrollmentLogin, accounts})
		return
	}
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password,omitempty"`
		Enabled    *bool  `json:"enabled,omitempty"`
		MaxDevices *int   `json:"max_devices,omitempty"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	defer clear(raw)
	if err := serverpool.DecodeStrict(raw, &req); readErr != nil || err != nil || !validEnrollmentUsername(req.Username) ||
		(req.Password != "" && (len(req.Password) < 8 || len(req.Password) > 72)) ||
		(req.MaxDevices != nil && (*req.MaxDevices < 1 || *req.MaxDevices > 32)) ||
		(req.Password == "" && req.Enabled == nil && req.MaxDevices == nil) {
		http.Error(w, "invalid account request (password 8..72 UTF-8 bytes, device limit 1..32)", 400)
		return
	}
	var hash string
	if req.Password != "" {
		select {
		case h.enrollmentSlots <- struct{}{}:
			defer func() { <-h.enrollmentSlots }()
		default:
			http.Error(w, "account authentication work busy", 429)
			return
		}
		value, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			http.Error(w, "password could not be stored", 400)
			return
		}
		hash = string(value)
	}
	if err := h.db.setEnrollmentAccount(r.Context(), req.Username, hash, req.Enabled, req.MaxDevices); err != nil {
		http.Error(w, "account update refused or unavailable; new accounts need a password", 409)
		return
	}
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (db *DB) setEnrollmentAccount(parent context.Context, username, newHash string, requestedEnabled *bool, requestedMax *int) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hash, enabled, maxDevices := "", true, 5
	err = tx.QueryRowContext(ctx, `SELECT password_hash,enabled,max_devices FROM enrollment_accounts WHERE username=?`, username).Scan(&hash, &enabled, &maxDevices)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollment_accounts`).Scan(&count); err != nil {
			return err
		}
		if newHash == "" || count >= 256 {
			return errors.New("new enrollment account refused")
		}
	}
	if newHash != "" {
		hash = newHash
	}
	if requestedEnabled != nil {
		enabled = *requestedEnabled
	}
	if requestedMax != nil {
		maxDevices = *requestedMax
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_accounts(username,password_hash,enabled,max_devices) VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,enabled=excluded.enabled,max_devices=excluded.max_devices,updated_at=CURRENT_TIMESTAMP`, username, hash, enabled, maxDevices); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('enrollment-account',?)`, "enrollment account updated: "+username+"; device approval is separate"); err != nil {
		return err
	}
	return tx.Commit()
}

func (h *Handler) enrollmentAccountsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, enrollmentAccountsHTML)
}

func (h *Handler) enrollmentAccountsScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = io.WriteString(w, enrollmentAccountsJS)
}

const enrollmentAccountsHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enrollment accounts</title><style>
body{font:14px/1.5 system-ui;background:#111;color:#fafafa;margin:24px}main{max-width:900px;margin:auto}a{color:#93c5fd}label{display:block;margin:12px 0}input,button{padding:8px}table{width:100%;text-align:left}td,th{padding:8px}#message{white-space:pre-wrap;color:#fbbf24}
</style></head><body><main><a href="/admin/">Back to panel</a><h1>Enrollment accounts</h1>
<p>User accounts authorize device enrollment only. They never log in to this administrator panel and never approve a device. Disabling an account stops new enrollment; revoke existing devices separately.</p>
<p id="policy"></p><form id="account-form"><label>Username <input id="username" required minlength="3" maxlength="64" autocomplete="off"></label>
<label>New password (leave empty to keep existing) <input id="password" type="password" autocomplete="new-password" maxlength="72"></label>
<label>Device limit <input id="max-devices" type="number" min="1" max="32" value="5" required></label><label><input id="enabled" type="checkbox" checked> Allow new enrollment</label>
<button type="submit">Save enrollment account</button></form><p id="message" role="status"></p><table><thead><tr><th>Username</th><th>New enrollment</th><th>Devices / limit</th></tr></thead><tbody id="accounts"></tbody></table>
</main><script src="/admin/enrollment-accounts.js" defer></script></body></html>`

const enrollmentAccountsJS = `"use strict";
const message=document.getElementById('message'), rows=document.getElementById('accounts'), form=document.getElementById('account-form');
async function load(){const r=await fetch('/admin/api/enrollment-accounts');if(!r.ok)throw new Error('Account inventory unavailable (HTTP '+r.status+')');const data=await r.json();document.getElementById('policy').textContent=data.login_required?'This pool requires a user login for new device enrollment.':'Login is not required by the current server configuration. Accounts do not change that policy.';rows.replaceChildren();for(const a of data.accounts){const row=document.createElement('tr');for(const value of [a.username,a.enabled?'Enabled':'Disabled',a.devices+' / '+a.max_devices]){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}rows.append(row);}}
form.addEventListener('submit',async e=>{e.preventDefault();const password=document.getElementById('password');try{if(password.value&&new TextEncoder().encode(password.value).length>72)throw new Error('Password exceeds 72 UTF-8 bytes');const body={username:document.getElementById('username').value,enabled:document.getElementById('enabled').checked,max_devices:Number(document.getElementById('max-devices').value)};if(password.value)body.password=password.value;const r=await fetch('/admin/api/enrollment-accounts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error('Account update refused (HTTP '+r.status+')');message.textContent='Saved. Device approval remains a separate administrator action.';await load();}catch(err){message.textContent=err.message;}finally{password.value='';}});
load().catch(err=>{message.textContent=err.message;});`
