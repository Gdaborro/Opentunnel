// killswitch-ui.js — extends the console's "Global Kill Switch" card with
// the reason field and the device allowlist (shipped as a runtime
// enhancement because the SPA bundle has no rebuild toolchain here).
// Loads current state, renders inline-styled controls under the card,
// and saves through the same /admin/api/settings endpoint the toggle uses.
(function () {
  "use strict";
  var state = { kill: false, reason: "", allow: [], devices: [] };
  var MARK = "otu-kill-ext";

  function el(tag, style, text) {
    var n = document.createElement(tag);
    if (style) n.setAttribute("style", style);
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function load() {
    return Promise.all([
      fetch("/admin/api/settings").then(function (r) { return r.json(); }),
      fetch("/admin/api/devices").then(function (r) { return r.json(); }).catch(function () { return []; }),
    ]).then(function (out) {
      var s = out[0] || {};
      state.kill = !!s.kill_switch;
      state.reason = s.kill_switch_reason || "";
      state.allow = s.kill_switch_allow || [];
      state.devices = out[1] || [];
      inject();
    }).catch(function () {});
  }

  function save(msgEl) {
    var reason = state.reason;
    var allow = state.allow;
    fetch("/admin/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kill_switch: state.kill, kill_switch_reason: reason, kill_switch_allow: allow }),
    }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      if (msgEl) { msgEl.textContent = "saved"; setTimeout(function () { msgEl.textContent = ""; }, 3000); }
    }).catch(function (e) {
      if (msgEl) msgEl.textContent = "save failed: " + e.message;
    });
  }

  function findCard() {
    var candidates = document.querySelectorAll("div[class]");
    var best = null;
    for (var i = 0; i < candidates.length; i++) {
      var c = candidates[i];
      if (c.className.indexOf("border-destructive") !== -1 && c.textContent.indexOf("Global Kill Switch") !== -1) {
        best = c;
        break; // first in document order is the outermost card
      }
    }
    return best;
  }

  function inject() {
    var card = findCard();
    if (!card) return;
    var next = card.nextElementSibling;
    if (next && next.getAttribute && next.getAttribute("data-" + MARK) === "1") {
      refresh(next);
      return; // already present
    }
    var box = el("div", "margin-top:12px;padding:14px;border:1px solid rgba(255,255,255,.1);border-radius:12px;background:rgba(255,255,255,.02);display:flex;flex-direction:column;gap:10px;font-size:13px");
    box.setAttribute("data-" + MARK, "1");

    var lbl1 = el("div", "font-weight:600", "Reason shown to every client while down");
    var ta = el("textarea", "width:100%;min-height:56px;background:#111113;color:inherit;border:1px solid rgba(255,255,255,.15);border-radius:8px;padding:8px 10px;font:inherit;resize:vertical");
    ta.value = state.reason;
    ta.placeholder = "Shut down till further notice";
    ta.oninput = function () { state.reason = ta.value; };

    var lbl2 = el("div", "font-weight:600", "Allowed devices keep browsing (per-device tokens)");
    var la = el("textarea", "width:100%;min-height:44px;background:#111113;color:inherit;border:1px solid rgba(255,255,255,.15);border-radius:8px;padding:8px 10px;font-family:ui-monospace,monospace;font-size:12px;resize:vertical");
    la.value = state.allow.join("\n");
    la.oninput = function () {
      state.allow = la.value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    };

    var devRow = el("div", "display:flex;flex-wrap:wrap;gap:6px");
    state.devices.slice(0, 12).forEach(function (d) {
      if (!d.token) return;
      var b = el("button", "cursor:pointer;border:1px solid rgba(255,255,255,.15);background:transparent;color:inherit;border-radius:999px;padding:3px 10px;font-size:12px",
        (d.device_name || d.token.slice(0, 8)) + (state.allow.indexOf(d.token) !== -1 ? " ✓" : " +"));
      b.title = d.token;
      b.onclick = function () {
        if (state.allow.indexOf(d.token) === -1) state.allow.push(d.token);
        la.value = state.allow.join("\n");
        b.textContent = (d.device_name || d.token.slice(0, 8)) + " ✓";
        save(msg);
      };
      devRow.appendChild(b);
    });

    var row = el("div", "display:flex;align-items:center;gap:12px");
    var saveBtn = el("button", "cursor:pointer;border:0;border-radius:8px;padding:8px 14px;font-weight:700;background:#fafafa;color:#111", "Save reason + allowlist");
    var msg = el("span", "font-size:12px;opacity:.8");
    saveBtn.onclick = function () { save(msg); };
    row.appendChild(saveBtn);
    row.appendChild(msg);

    box.appendChild(lbl1); box.appendChild(ta);
    box.appendChild(lbl2); box.appendChild(la);
    if (devRow.childNodes.length) box.appendChild(devRow);
    box.appendChild(row);
    card.parentNode.insertBefore(box, card.nextSibling);
  }

  function refresh(box) {
    // Keep textareas in sync when the page reloads state elsewhere.
    var tas = box.querySelectorAll("textarea");
    if (tas.length >= 1 && document.activeElement !== tas[0]) tas[0].value = state.reason;
    if (tas.length >= 2 && document.activeElement !== tas[1]) tas[1].value = state.allow.join("\n");
  }

  function boot() {
    load();
    var pending = null;
    var mo = new MutationObserver(function () {
      if (pending) return;
      pending = setTimeout(function () { pending = null; inject(); }, 250);
    });
    mo.observe(document.body, { childList: true, subtree: true });
    // The settings may also change server-side; refresh periodically.
    setInterval(load, 30000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
