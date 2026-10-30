// ssh-tier-ui.js — extends the console's System page with the ssh-tier
// containment card: sustained per-device cap, daily byte budget and the
// post-budget trickle rate for the ssh transport's ingress (the relay
// enforces these via internal/server/sshtier.go). Runtime enhancement
// because the SPA bundle has no rebuild toolchain here; the native
// version lives in panel-ui/src/pages/system.tsx for future rebuilds.
(function () {
  "use strict";
  var state = { maxMbps: 0, dailyMB: 0, trickleKbps: 0 };
  var MARK = "otu-sshtier-ext";

  function el(tag, style, text) {
    var n = document.createElement(tag);
    if (style) n.setAttribute("style", style);
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function load() {
    fetch("/admin/api/settings")
      .then(function (r) { return r.json(); })
      .then(function (s) {
        s = s || {};
        var bps = Number(s.ssh_tier_max_bps) || 0;
        state.maxMbps = bps ? +(bps * 8 / 1e6).toFixed(3) : 0;
        state.dailyMB = Number(s.ssh_tier_daily_mb) || 0;
        state.trickleKbps = Number(s.ssh_tier_trickle_kbps) || 0;
        inject();
      })
      .catch(function () {});
  }

  function save(msgEl) {
    fetch("/admin/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh_tier_max_bps: Math.max(0, Math.round(state.maxMbps * 1e6 / 8)),
        ssh_tier_daily_mb: Math.max(0, Math.round(state.dailyMB)),
        ssh_tier_trickle_kbps: Math.max(0, Math.round(state.trickleKbps)),
      }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        if (msgEl) { msgEl.textContent = "saved"; setTimeout(function () { msgEl.textContent = ""; }, 3000); }
      })
      .catch(function (e) {
        if (msgEl) msgEl.textContent = "save failed: " + e.message;
      });
  }

  // Anchor: the innermost card containing "Relay Configuration" (System
  // page); the containment card slots in just above it, after the
  // kill-switch card.
  function findAnchor() {
    var best = null;
    var all = document.querySelectorAll("div[class]");
    for (var i = 0; i < all.length; i++) {
      var c = all[i];
      var cls = String(c.className || "");
      if (cls.indexOf("border") === -1) continue;
      if (c.textContent.indexOf("Relay Configuration") !== -1) best = c;
    }
    return best;
  }

  function numField(labelText, hint, value, inputStyle, onChange) {
    var wrap = el("div", "display:flex;flex-direction:column;gap:4px");
    wrap.appendChild(el("div", "font-weight:600", labelText));
    var inp = el("input", inputStyle || "width:130px;background:#111113;color:inherit;border:1px solid rgba(255,255,255,.15);border-radius:8px;padding:6px 10px;font:inherit");
    inp.type = "number";
    inp.min = "0";
    inp.step = "1";
    inp.value = String(value);
    inp.oninput = function () { onChange(inp.value); };
    wrap.appendChild(inp);
    wrap.appendChild(el("div", "font-size:11px;opacity:.65", hint));
    return wrap;
  }

  function build() {
    var box = el("div", "margin-top:16px;padding:14px;border:1px solid rgba(255,255,255,.1);border-radius:12px;background:rgba(255,255,255,.02);display:flex;flex-direction:column;gap:10px;font-size:13px");
    box.setAttribute("data-" + MARK, "1");
    box.appendChild(el("div", "font-weight:700", "SSH-tier containment"));
    box.appendChild(el("div", "font-size:12px;opacity:.75",
      "Keeps the ssh transport — the only tier that survives TLS interception with blocked UDP — from reading as a media relay: cap each device's sustained rate and give it a daily byte budget. After the budget is spent, new streams degrade to the post-budget rate (pages keep loading, video cannot)."));

    var row = el("div", "display:flex;gap:18px;flex-wrap:wrap");
    row.appendChild(numField("Sustained cap (Mbps, 0 = off)",
      "Per device, applies to ssh ingress only",
      state.maxMbps,
      null,
      function (v) { state.maxMbps = Math.max(0, Number(v) || 0); }));
    row.appendChild(numField("Daily budget (MB, 0 = off)",
      "Per device; resets at UTC midnight",
      state.dailyMB,
      null,
      function (v) { state.dailyMB = Math.max(0, Number(v) || 0); }));
    row.appendChild(numField("Post-budget rate (kbps, 0 = default 200)",
      "Applied once the daily budget is spent",
      state.trickleKbps,
      null,
      function (v) { state.trickleKbps = Math.max(0, Number(v) || 0); }));
    box.appendChild(row);

    var foot = el("div", "display:flex;align-items:center;gap:12px");
    var saveBtn = el("button", "cursor:pointer;border:0;border-radius:8px;padding:8px 14px;font-weight:700;background:#fafafa;color:#111", "Save containment policy");
    var msg = el("span", "font-size:12px;opacity:.8");
    saveBtn.onclick = function () { save(msg); };
    foot.appendChild(saveBtn);
    foot.appendChild(msg);
    box.appendChild(foot);
    return box;
  }

  function refresh(box) {
    var inps = box.querySelectorAll("input[type=number]");
    var vals = [state.maxMbps, state.dailyMB, state.trickleKbps];
    for (var i = 0; i < inps.length && i < 3; i++) {
      if (document.activeElement !== inps[i]) inps[i].value = String(vals[i]);
    }
  }

  function inject() {
    var anchor = findAnchor();
    if (!anchor) return;
    var prev = anchor.previousElementSibling;
    if (prev && prev.getAttribute && prev.getAttribute("data-" + MARK) === "1") {
      refresh(prev);
      return; // already present
    }
    var box = build();
    anchor.parentNode.insertBefore(box, anchor);
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
