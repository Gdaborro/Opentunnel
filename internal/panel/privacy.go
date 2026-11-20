package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"opentunnel/internal/serverpool"
)

type PrivacyPolicy struct {
	Mode       string `json:"mode"`                 // preserve (existing fleet behavior) or minimal (explicit opt-in)
	VisitDays  int    `json:"visit_retention_days"` // 0 preserves legacy no age-based purge
	HealthDays int    `json:"health_retention_days"`
	IPDays     int    `json:"peer_ip_retention_days"`
}

func readPrivacyPolicy(ctx context.Context, reader policyReader) (PrivacyPolicy, error) {
	p := PrivacyPolicy{Mode: "preserve", IPDays: 7}
	var mode, visits, health, ips string
	err := reader.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='telemetry_mode'),'preserve'),COALESCE((SELECT value FROM settings WHERE key='visit_retention_days'),'0'),COALESCE((SELECT value FROM settings WHERE key='health_retention_days'),'0'),COALESCE((SELECT value FROM settings WHERE key='peer_ip_retention_days'),'7')`).Scan(&mode, &visits, &health, &ips)
	if err != nil {
		return p, err
	}
	p.Mode = mode
	for _, field := range []struct {
		raw string
		dst *int
	}{{visits, &p.VisitDays}, {health, &p.HealthDays}, {ips, &p.IPDays}} {
		n, err := strconv.Atoi(field.raw)
		if err != nil {
			return p, errors.New("invalid retention policy")
		}
		*field.dst = n
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func (p PrivacyPolicy) Validate() error {
	if (p.Mode != "preserve" && p.Mode != "minimal") || p.VisitDays < 0 || p.VisitDays > 90 || p.HealthDays < 0 || p.HealthDays > 90 || p.IPDays < 1 || p.IPDays > 30 {
		return errors.New("mode preserve/minimal; visit/health retention 0..90 days; IP history 1..30 days")
	}
	return nil
}

func (db *DB) PrivacyPolicy() (PrivacyPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return readPrivacyPolicy(ctx, db)
}

func (db *DB) SetPrivacyPolicy(parent context.Context, p PrivacyPolicy, applyNow bool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, value := range []struct{ key, value string }{{"telemetry_mode", p.Mode}, {"visit_retention_days", strconv.Itoa(p.VisitDays)}, {"health_retention_days", strconv.Itoa(p.HealthDays)}, {"peer_ip_retention_days", strconv.Itoa(p.IPDays)}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, value.key, value.value); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('privacy','operator explicitly changed telemetry/retention; approval, bans, filtering and accounting unchanged')`); err != nil {
		return err
	}
	if applyNow {
		if err := applyPrivacyRetention(ctx, tx, p); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func applyPrivacyRetention(ctx context.Context, tx *sql.Tx, p PrivacyPolicy) error {
	for _, rule := range []struct {
		table, column string
		days          int
	}{{"visits", "last_seen", p.VisitDays}, {"device_health", "at", p.HealthDays}, {"peer_ips", "at", p.IPDays}} {
		if rule.days == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+rule.table+` WHERE `+rule.column+`<datetime('now',?)`, "-"+strconv.Itoa(rule.days)+" days"); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) PrunePrivacyRetention(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPrivacyPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if err := applyPrivacyRetention(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit()
}

func (h *Handler) privacyAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		p, err := h.db.PrivacyPolicy()
		if err != nil {
			http.Error(w, "privacy policy unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
		return
	}
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Policy   PrivacyPolicy `json:"policy"`
		ApplyNow bool          `json:"apply_retention_now"`
		Confirm  bool          `json:"confirm_retention_purge"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil || serverpool.DecodeStrict(raw, &req) != nil || req.ApplyNow != req.Confirm {
		http.Error(w, "invalid privacy request; immediate purge needs explicit confirmation", 400)
		return
	}
	if err := req.Policy.Validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := h.db.SetPrivacyPolicy(r.Context(), req.Policy, req.ApplyNow); err != nil {
		http.Error(w, "privacy update unavailable; nothing changed", 503)
		return
	}
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (db *DB) telemetryAllowed() bool {
	p, err := db.PrivacyPolicy()
	return err == nil && p.Mode == "preserve"
}

func (h *Handler) privacyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, privacyHTML)
}
func (h *Handler) privacyScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = io.WriteString(w, privacyJS)
}

const privacyHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>OTU privacy and retention</title><body><main><h1>Privacy and retention</h1><p>Existing monitoring remains unchanged until you explicitly opt in. Minimal mode stops domain visits, IP history and hardware posture storage. Device versions and aggregate quota/abuse controls remain. This is not anonymity: relay operators can observe traffic.</p><form id="privacy"><fieldset id="controls" disabled><legend>Explicit storage policy</legend><label for="mode">Telemetry</label> <select id="mode"><option value="preserve">Preserve fleet monitoring</option><option value="minimal">Minimal (opt-in)</option></select><p><label for="visits">Visit retention days (0 keeps legacy age behavior)</label> <input id="visits" type="number" min="0" max="90" required></p><p><label for="health">Health retention days (0 keeps latest sample)</label> <input id="health" type="number" min="0" max="90" required></p><p><label for="ips">IP history retention days</label> <input id="ips" type="number" min="1" max="30" required></p><p><label><input id="purge" type="checkbox">Apply these age limits to existing records now (deletes expired telemetry only)</label></p><button type="submit">Save explicit policy</button></fieldset></form><button id="refresh" type="button">Refresh policy</button><p id="result" role="status" aria-live="polite">Reading authoritative policy…</p><p><a href="/admin/">Back to panel</a></p></main><script src="/admin/privacy.js"></script></body></html>`
const privacyJS = `const byId=id=>document.getElementById(id);let busy=false,loaded=false;async function read(){const r=await fetch('/admin/api/privacy',{cache:'no-store'});if(!r.ok)throw Error('Policy unavailable');return r.json();}function apply(p){byId('mode').value=p.mode;byId('visits').value=p.visit_retention_days;byId('health').value=p.health_retention_days;byId('ips').value=p.peer_ip_retention_days;}async function load(){if(busy)return;busy=true;loaded=false;byId('controls').disabled=true;try{apply(await read());loaded=true;byId('controls').disabled=false;byId('result').textContent='Policy read from the authority. No policy changed by this read.';}catch{byId('result').textContent='Policy unavailable. No defaults substituted; refresh before editing.';}finally{busy=false;}}byId('refresh').addEventListener('click',load);byId('privacy').addEventListener('submit',async e=>{e.preventDefault();if(busy||!loaded)return;const purge=byId('purge').checked;if(purge&&!confirm('Delete telemetry older than the selected retention limits? Identity bans, approval and accounting will not change.'))return;const policy={mode:byId('mode').value,visit_retention_days:Number(byId('visits').value),health_retention_days:Number(byId('health').value),peer_ip_retention_days:Number(byId('ips').value)};busy=true;byId('controls').disabled=true;try{const r=await fetch('/admin/api/privacy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({policy,apply_retention_now:purge,confirm_retention_purge:purge})});if(!r.ok)throw Error('write unavailable');const verified=await read();if(Object.keys(policy).some(key=>policy[key]!==verified[key]))throw Error('concurrent policy change');apply(verified);byId('purge').checked=false;byId('result').textContent='Saved and verified. Approval, bans, filtering and quota accounting remain enforced.';byId('controls').disabled=false;}catch{loaded=false;byId('result').textContent='Save or read-back failed. Policy state is unconfirmed; refresh before retrying.';}finally{busy=false;}});load();`
