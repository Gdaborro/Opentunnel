package authority

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"opentunnel/internal/metrics"
	"opentunnel/internal/panelproxy"
	"opentunnel/internal/serverpool"
)

type Handler struct {
	store        Store
	info         serverpool.Info
	nodes        Nodes
	public       http.Handler
	slots        chan struct{}
	accountSlots chan struct{}
	publicSlots  chan struct{}
	nodeSlots    map[string]chan struct{}
}

func NewHandler(store Store, info serverpool.Info, nodes Nodes, public http.Handler) (*Handler, error) {
	if store == nil || !serverpool.ValidID(info.PoolID) || !serverpool.ValidID(info.AuthorityID) || !info.ApprovalRequired || !info.RequireChannelAuth || info.Version != serverpool.ChannelProfileVersion {
		return nil, errors.New("remote authority requires a bound manually approved connection-authenticated pool")
	}
	if err := nodes.Validate(); err != nil {
		return nil, err
	}
	owned := Nodes{Nodes: make([]Node, len(nodes.Nodes))}
	for i, n := range nodes.Nodes {
		owned.Nodes[i] = Node{ID: n.ID, Pins: append([]string(nil), n.Pins...)}
	}
	h := &Handler{store: store, info: info, nodes: owned, public: public, slots: make(chan struct{}, 32), accountSlots: make(chan struct{}, 32), publicSlots: make(chan struct{}, 8), nodeSlots: map[string]chan struct{}{}}
	for _, node := range owned.Nodes {
		h.nodeSlots[node.ID] = make(chan struct{}, 16)
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 1 {
		http.Error(w, "mutually authenticated node required", 403)
		return
	}
	node, err := nodeForCertificate(h.nodes, r.TLS.PeerCertificates[0])
	if err != nil || r.Header.Get("X-Otu-Node") != node || r.Header.Get("X-Otu-Pool") != h.info.PoolID || r.Header.Get("X-Otu-Authority") != h.info.AuthorityID {
		http.Error(w, "node/authority scope mismatch", 403)
		return
	}
	select {
	case h.nodeSlots[node] <- struct{}{}:
		defer func() { <-h.nodeSlots[node] }()
	default:
		http.Error(w, "node request capacity reached", 429)
		return
	}
	path := r.URL.EscapedPath()
	if path != r.URL.Path || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, "invalid authority path", 400)
		return
	}
	if strings.HasPrefix(path, "/api/token/") {
		if h.public == nil || !publicTokenPath(path) {
			http.NotFound(w, r)
			return
		}
		select {
		case h.publicSlots <- struct{}{}:
			defer func() { <-h.publicSlots }()
		default:
			http.Error(w, "authority public capacity reached", 429)
			return
		}
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		// Only an authenticated node supplies the resolved source address.
		clone.RemoteAddr = "127.0.0.1:1"
		clone.Header.Set(panelproxy.SchemeHeader, "https")
		clone = panelproxy.MarkAuthority(clone)
		h.public.ServeHTTP(w, clone)
		return
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(path, APIPath) {
		http.NotFound(w, r)
		return
	}
	op := strings.TrimPrefix(path, APIPath)
	slots := h.slots
	if op == "reserve" || op == "settle" {
		slots = h.accountSlots
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		http.Error(w, "authority capacity reached", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	defer clear(raw)
	if err != nil {
		http.Error(w, "invalid authority request", 400)
		return
	}
	write := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
	decode := func(v any) bool {
		if serverpool.DecodeStrict(raw, v) != nil {
			http.Error(w, "invalid authority schema", 400)
			return false
		}
		return true
	}
	failure := func(err error) {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "unknown device", 404)
		} else if errors.Is(err, ErrDenied) {
			http.Error(w, "request denied", 409)
		} else {
			http.Error(w, "authority operation unavailable; traffic denied", 503)
		}
	}
	switch op {
	case "info":
		if !decode(&struct{}{}) {
			return
		}
		write(h.info)
	case "policy":
		var req TokenRequest
		if !decode(&req) {
			return
		}
		if !ValidToken(req.Token) {
			http.Error(w, "invalid token", 400)
			return
		}
		p, err := h.store.AccessPolicy(req.Token)
		if err != nil {
			failure(err)
			return
		}
		if p.PoolID != h.info.PoolID || p.AuthorityID != h.info.AuthorityID || !p.ChannelRequired {
			failure(ErrUnavailable)
			return
		}
		write(p)
	case "authenticate":
		var req AuthRequest
		if !decode(&req) {
			return
		}
		if !ValidToken(req.Token) || !ValidGeneration(req.Generation) || len(req.PublicKey) > 2048 || !req.ChannelBound {
			http.Error(w, "channel-bound device identity required", 400)
			return
		}
		if err := h.store.CommitAuthentication(req.Token, req.Generation, req.PublicKey, true); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "block":
		var req BlockRequest
		if !decode(&req) {
			return
		}
		if len(req.Domain) < 1 || len(req.Domain) > 253 {
			http.Error(w, "invalid filtering target", 400)
			return
		}
		blocked, reason, err := h.store.CheckBlocked(req.Domain)
		if err != nil {
			failure(err)
			return
		}
		write(BlockResponse{blocked, reason})
	case "reserve":
		var req ReserveRequest
		if !decode(&req) {
			return
		}
		if req.Validate(time.Now()) != nil {
			http.Error(w, "invalid reservation", 400)
			return
		}
		reservation, err := h.store.ReserveNodeTraffic(ctx, node, req)
		if err != nil {
			failure(err)
			return
		}
		write(reservation)
	case "settle":
		var req Settlement
		if !decode(&req) {
			return
		}
		if _, err := ReservationTime(req.ID); err != nil || !ValidToken(req.Token) || !ValidGeneration(req.Generation) || req.Refund < 0 || req.Refund > 65535 {
			http.Error(w, "invalid settlement", 400)
			return
		}
		if err := h.store.SettleNodeTraffic(ctx, node, req); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "control":
		var req ControlRequest
		if !decode(&req) {
			return
		}
		if !ValidToken(req.Token) || !ValidGeneration(req.Generation) || len(req.PublicKey) > 2048 || (req.Request.Op != "status" && req.Request.Op != "health") {
			http.Error(w, "invalid control request", 400)
			return
		}
		resp, err := h.store.ControlBound(ctx, req)
		if err != nil {
			failure(err)
			return
		}
		write(resp)
	case "peer-ip":
		var req PeerIPRequest
		if !decode(&req) {
			return
		}
		if err := h.store.SetPeerIPBound(ctx, req); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "visit":
		var req VisitRequest
		if !decode(&req) {
			return
		}
		if err := h.store.RecordVisitBound(ctx, req); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "event":
		var req EventRequest
		if !decode(&req) {
			return
		}
		if err := h.store.RecordNodeEvent(ctx, node, req); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "metrics":
		var req metrics.Snapshot
		if !decode(&req) {
			return
		}
		if err := h.store.RecordNodeMetrics(ctx, node, req); err != nil {
			failure(err)
			return
		}
		write(OK{true})
	case "setting":
		var req SettingRequest
		if !decode(&req) {
			return
		}
		if req.Key != "sentinel_mode" {
			http.Error(w, "setting not exposed to relay nodes", 403)
			return
		}
		value, err := h.store.AuthoritySetting(ctx, req.Key)
		if err != nil {
			failure(err)
			return
		}
		write(SettingResponse{value})
	default:
		http.NotFound(w, r) // no approve/rekey/admin/database/SSH-file operations
	}
}

func publicTokenPath(path string) bool {
	switch path {
	case serverpool.InfoPath, "/api/token/request", "/api/token/status", "/api/token/heartbeat", "/api/token/health":
		return true
	default:
		return false
	}
}
