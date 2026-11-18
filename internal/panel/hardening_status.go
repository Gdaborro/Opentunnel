package panel

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) hardeningStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	privacy, err := h.db.PrivacyPolicy()
	if err != nil {
		http.Error(w, "privacy policy unavailable", 503)
		return
	}
	nodes, err := h.db.NodeMetrics(r.Context())
	if err != nil {
		http.Error(w, "node diagnostics unavailable", 503)
		return
	}
	var desired, revoked, verified, devices int
	if err := h.db.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(desired=1),0),COALESCE(SUM(desired=0),0) FROM managed_ssh_keys`).Scan(&desired, &revoked); err != nil {
		http.Error(w, "SSH inventory unavailable", 503)
		return
	}
	if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*),COALESCE(SUM(channel_seen=1 AND channel_epoch=auth_epoch AND auth_epoch!=''),0) FROM peers`).Scan(&devices, &verified); err != nil {
		http.Error(w, "migration state unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"privacy": privacy, "relay_nodes": nodes, "channel_verified_current_identities": verified, "device_count": devices, "managed_ssh_desired": desired, "managed_ssh_revoked": revoked, "ssh_apply_status": "inspect ssh_reconcile_pending action response; periodic reconcile retries", "release_acceptance": "not certified by this runtime API"})
}
