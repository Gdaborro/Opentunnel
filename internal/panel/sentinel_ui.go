package panel

import (
	"net/http"
)

// sentinelPage is a standalone admin console for the proactive sentinel
// (v1.1.0), mirroring the kill-switch page: no SPA rebuild needed. It lets
// the operator switch the response mode (off | alert | respond) and watch
// recent findings.
func (h *Handler) sentinelPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(sentinelHTML))
}

const sentinelHTML = `<!doctype html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>otu — sentinel</title>
<style>
  :root{--bg:#0d0d0f;--card:#18181b;--fg:#fafafa;--muted:#a1a1aa;--border:rgba(255,255,255,.1);--red:#f87171;--green:#4ade80;--amber:#fbbf24}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:24px}
  main{width:100%;max-width:720px;display:flex;flex-direction:column;gap:16px}
  h1{font-size:18px;margin:0}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px}
  label{font-weight:600;font-size:13px}
  button{background:#2a2a2e;color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:9px 14px;font-weight:600;cursor:pointer}
  button.active{background:var(--green);color:#0a1a0a;border-color:transparent}
  .row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .state{font-weight:700}
  .muted{color:var(--muted);font-size:12px}
  table{border-collapse:collapse;width:100%;font-size:12px}
  td,th{border-bottom:1px solid var(--border);text-align:left;padding:5px 6px;vertical-align:top}
  .sev-critical{color:var(--red);font-weight:700}.sev-warning{color:var(--amber)}.sev-info{color:var(--muted)}
  #msg{min-height:18px;font-size:12px;color:var(--amber)}
</style>
</head>
<body>
<main>
  <h1>otu sentinel — proactive detection</h1>
  <div class="card">
    <div class="row">
      <span>Response mode:</span>
      <span id="mode" class="state">…</span>
    </div>
    <div class="row">
      <button id="m_off" type="button">Off (silent)</button>
      <button id="m_alert" type="button">Alert only</button>
      <button id="m_respond" type="button">Alert + auto-respond</button>
      <span id="msg"></span>
    </div>
    <p class="muted">respond mode: auth-failure floods ban the source IP for 30 min; impossible travel may temporarily kick a device. Invalid-signature and downgrade attempts raise critical alerts but cannot kick their named victim. Actions self-expire and operator-allowlisted devices are exempt from auto-kicks. All findings appear under Alerts.</p>
  </div>
  <div class="card">
    <div class="row">
      <label>Recent findings — last 24 h: <span id="c24">–</span></label>
      <button id="refresh" type="button">refresh</button>
    </div>
    <table id="alerts"><thead><tr><th>severity</th><th>message</th><th>at</th></tr></thead><tbody></tbody></table>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
let mode = 'respond';
function esc(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function msg(t){ $('msg').textContent = t; setTimeout(()=>{ $('msg').textContent=''; }, 4000); }
function paint(){
  $('mode').textContent = mode;
  for (const m of ['off','alert','respond']) $('m_'+m).className = (m===mode ? 'active' : '');
}
function load(){
  fetch('/admin/api/sentinel').then(r=>r.json()).then(s=>{
    mode = s.mode || 'respond';
    $('c24').textContent = s.alerts_24h;
    paint();
    const tb = $('alerts').querySelector('tbody'); tb.innerHTML='';
    (s.recent||[]).forEach(a=>{
      const tr = document.createElement('tr');
      tr.innerHTML = '<td class="sev-'+esc(a.severity)+'">'+esc(a.severity)+'</td><td>'+esc(a.message)+'</td><td class="muted">'+esc(a.at)+'</td>';
      tb.appendChild(tr);
    });
  }).catch(()=>msg('failed to load'));
}
function setMode(m){
  fetch('/admin/api/sentinel', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mode:m})})
    .then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); mode=m; paint(); msg('mode = '+m+' (relay picks it up within ~15 s)'); })
    .catch(e=>msg('save failed: '+e.message));
}
$('m_off').onclick = () => setMode('off');
$('m_alert').onclick = () => setMode('alert');
$('m_respond').onclick = () => setMode('respond');
$('refresh').onclick = load;
load(); setInterval(load, 30000);
</script>
</body>
</html>
`
