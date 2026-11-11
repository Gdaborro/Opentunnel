package panel

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/ssh"
)

func (h *Handler) sshKeysPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(sshKeysHTML))
}

func (h *Handler) sshKeysScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(sshKeysJS))
}

func (h *Handler) sshKeysAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := h.db.Query(`SELECT token, COALESCE(device_name,''), status, COALESCE(ssh_pubkey,'') FROM peers ORDER BY device_name`)
	if err != nil {
		http.Error(w, "key inventory unavailable", http.StatusServiceUnavailable)
		return
	}
	defer rows.Close()
	type device struct {
		Token       string `json:"token"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		PublicKey   string `json:"ssh_pubkey"`
		Fingerprint string `json:"ssh_fingerprint"`
	}
	devices := []device{}
	for rows.Next() {
		var d device
		if rows.Scan(&d.Token, &d.Name, &d.Status, &d.PublicKey) != nil {
			continue
		}
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.PublicKey)); err == nil {
			d.Fingerprint = ssh.FingerprintSHA256(key)
		}
		devices = append(devices, d)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(devices)
}

const sshKeysHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device SSH-key recovery</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;background:#0d0d0f;color:#fafafa;margin:24px}
main{max-width:960px;margin:auto}a{color:#93c5fd}article{border:1px solid #444;border-radius:12px;padding:16px;margin:12px 0}
code{overflow-wrap:anywhere}input{width:100%;box-sizing:border-box;padding:10px;margin:10px 0;background:#18181b;color:#fafafa;border:1px solid #666}
button{padding:9px 12px;margin-right:8px;cursor:pointer}#message{white-space:pre-wrap;color:#fbbf24}
</style></head><body><main><a href="/admin/">Back to panel</a>
<h1>Device SSH-key recovery</h1>
<p>Use only public keys. Verify the new SHA256 fingerprint directly with the device owner before replacing a key.
Replacement revokes the old key and returns the device to pending. Approval is a separate, deliberate action.</p>
<p id="message" role="status"></p><div id="devices"></div>
</main><script src="/admin/ssh-keys.js" defer></script></body></html>`

const sshKeysJS = `"use strict";
const devices = document.getElementById('devices');
const message = document.getElementById('message');
async function api(path, body) {
  const options = body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};
  const r = await fetch(path, options);
  if (!r.ok) throw new Error('HTTP '+r.status+': '+await r.text());
  return r.json();
}
async function fingerprint(key) {
  const parts = key.trim().split(/\s+/);
  if (parts.length < 2 || parts[0] !== 'ssh-ed25519') throw new Error('Enter one ssh-ed25519 public key, never a private key.');
  const blob = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', blob));
  return 'SHA256:'+btoa(String.fromCharCode(...hash)).replace(/=+$/, '');
}
async function load() {
  const rows = await api('/admin/api/ssh-keys');
  devices.replaceChildren();
  for (const d of rows) {
    const card = document.createElement('article');
    const title = document.createElement('h2'); title.textContent = (d.name || 'Unnamed device')+' ('+d.status+')';
    const current = document.createElement('p'); current.textContent = 'Current public-key fingerprint: '+(d.ssh_fingerprint || 'No usable key');
    const input = document.createElement('input'); input.placeholder = 'Verified replacement: ssh-ed25519 ...'; input.autocomplete = 'off';
    const replace = document.createElement('button'); replace.textContent = 'Verify and replace key';
    replace.onclick = async () => {
      try {
        const fp = await fingerprint(input.value);
        if (!confirm('Verify this fingerprint with the device owner:\n'+fp+'\n\nRevoke the old key and return this device to pending?')) return;
        await api('/admin/api/peers/'+encodeURIComponent(d.token)+'/rekey', {ssh_pubkey:input.value.trim(),expected_ssh_pubkey:d.ssh_pubkey,confirm:true});
        message.textContent = 'Key replaced. Confirm the device identity, then approve it separately.'; await load();
      } catch (e) { message.textContent = e.message; }
    };
    card.append(title, current, input, replace);
    if (d.status === 'pending') {
      const approve = document.createElement('button'); approve.textContent = 'Approve verified device';
      approve.onclick = async () => {
        try {
          if (!confirm('Approve this device after verifying its current public-key fingerprint?')) return;
          await api('/admin/api/peers/'+encodeURIComponent(d.token)+'/approve', {}); await load();
        } catch (e) { message.textContent = e.message; }
      };
      card.append(approve);
    }
    devices.append(card);
  }
}
load().catch(e => { message.textContent = e.message; });`
