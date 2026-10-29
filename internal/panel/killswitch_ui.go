package panel

import (
	"net/http"
)

// killswitchPage is a standalone admin console (no SPA rebuild needed):
// toggle the switch, set the client-visible reason, and manage the
// allowlist that keeps the operator's own devices tunneling.
func (h *Handler) killswitchPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(killswitchHTML))
}

const killswitchHTML = `<!doctype html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>otu — kill switch</title>
<style>
  :root{--bg:#0d0d0f;--card:#18181b;--fg:#fafafa;--muted:#a1a1aa;--border:rgba(255,255,255,.1);--red:#f87171;--green:#4ade80;--amber:#fbbf24}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:24px}
  main{width:100%;max-width:640px;display:flex;flex-direction:column;gap:16px}
  h1{font-size:18px;margin:0}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px}
  label{font-weight:600;font-size:13px}
  textarea,input{width:100%;background:#111113;color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:9px 11px;font:inherit}
  textarea{min-height:72px;resize:vertical}
  button{background:var(--red);color:#150505;border:0;border-radius:8px;padding:10px 16px;font-weight:700;cursor:pointer}
  button.on{background:var(--green)}
  .row{display:flex;align-items:center;justify-content:space-between;gap:12px}
  .state{font-weight:700}
  .state.on{color:var(--red)}.state.off{color:var(--green)}
  .muted{color:var(--muted);font-size:12px}
  .dev{display:flex;gap:8px;align-items:center;font-size:12px}
  table{border-collapse:collapse;width:100%;font-size:12px}
  td,th{border-bottom:1px solid var(--border);text-align:left;padding:4px 6px}
  .save{background:var(--fg);color:#111}
  #msg{min-height:18px;font-size:12px;color:var(--amber)}
</style>
</head>
<body>
<main>
  <h1>otu kill switch</h1>
  <div class="card">
    <div class="row">
      <span>Traffic:</span>
      <span id="state" class="state off">…</span>
      <button id="toggle" type="button">toggle</button>
    </div>
    <div>
      <label for="reason">Reason shown on every client while down</label>
      <textarea id="reason" placeholder="Shut down till further notice"></textarea>
    </div>
    <div>
      <label for="allow">Allowed devices (one token per line — these keep browsing)</label>
      <textarea id="allow" placeholder="paste device tokens here"></textarea>
      <p class="muted">Use the table below to copy your own device's token.</p>
    </div>
    <div class="row">
      <button id="save" class="save" type="button">Save reason + allowlist</button>
      <span id="msg"></span>
    </div>
  </div>
  <div class="card">
    <label>Devices</label>
    <table id="devs"><thead><tr><th>token</th><th>name</th><th>status</th><th></th></tr></thead><tbody></tbody></table>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
let kill = false;
function msg(t){ $('msg').textContent = t; setTimeout(()=>{ $('msg').textContent=''; }, 4000); }
function paint(){ const s=$('state'); s.textContent = kill ? 'DOWN — suspended (allowlist keeps browsing)' : 'up'; s.className = 'state ' + (kill?'on':'off'); $('toggle').className = kill?'on':''; $('toggle').textContent = kill ? 'Bring traffic back up' : 'Take traffic down'; }
function load(){ fetch('/admin/api/settings').then(r=>r.json()).then(s=>{ kill=!!s.kill_switch; $('reason').value=s.kill_switch_reason||''; $('allow').value=(s.kill_switch_allow||[]).join('\n'); paint(); }).catch(()=>msg('failed to load settings')); }
function devices(){ fetch('/admin/api/devices').then(r=>r.json()).then(list=>{ const tb=$('devs').querySelector('tbody'); tb.innerHTML=''; (list||[]).forEach(d=>{ const tr=document.createElement('tr'); tr.innerHTML='<td class="muted">'+String(d.token).slice(0,10)+'…</td><td>'+esc(d.device_name||'')+'</td><td>'+esc(d.status||'')+'</td>'; const b=document.createElement('button'); b.textContent='allow'; b.className='save'; b.onclick=()=>{ const cur=$('allow').value.trim().split('\n').filter(Boolean); if(!cur.includes(d.token)) cur.push(d.token); $('allow').value=cur.join('\n'); msg('added — click Save to apply'); }; const td=document.createElement('td'); td.appendChild(b); tr.appendChild(td); tb.appendChild(tr); }); }).catch(()=>{}); }
function esc(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function save(extra){
  const body = Object.assign({
    kill_switch: kill,
    kill_switch_reason: $('reason').value,
    kill_switch_allow: $('allow').value.split('\n').map(s=>s.trim()).filter(Boolean),
  }, extra||{});
  fetch('/admin/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); msg('saved'); })
    .catch(e=>msg('save failed: '+e.message));
}
$('toggle').onclick = () => { kill = !kill; paint(); save(); };
$('save').onclick = () => save();
load(); devices();
</script>
</body>
</html>
`
