package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net"
	"time"

	"opentunnel/internal/access"
	"opentunnel/internal/authority"
	"opentunnel/internal/metrics"
	"opentunnel/internal/protocol"
)

func boundAuthorityPolicy(ctx context.Context, tx *sql.Tx, token, generation, publicKey string) (access.Snapshot, error) {
	if !authority.ValidToken(token) || !authority.ValidGeneration(generation) || len(publicKey) > 2048 {
		return access.Snapshot{}, authority.ErrDenied
	}
	p, err := accessPolicy(ctx, tx, token)
	if err != nil {
		return p, err
	}
	if p.Generation != generation || p.PublicKey != publicKey || !p.ChannelVerified {
		return p, authority.ErrDenied
	}
	return p, nil
}

func validHealth(req protocol.CtrlRequest) bool {
	if len(req.Version) > 64 || len(req.OS) > 32 || len(req.Arch) > 32 || req.UptimeS < 0 || len(req.UpdateChannel) > 16 || len(req.UpdateState) > 128 {
		return false
	}
	for _, value := range []struct{ n, max float64 }{{req.CPUPct, 100}, {req.MemPct, 100}, {req.TempC, 250}, {req.LatencyMs, 600000}, {req.JitterMs, 600000}, {req.ProbeLossPct, 100}} {
		if math.IsNaN(value.n) || math.IsInf(value.n, 0) || value.n < 0 || value.n > value.max {
			return false
		}
	}
	return true
}

// ControlBound makes liveness/telemetry mutation conditional on one current
// generation/key/admission transaction. A revoked session cannot race an old
// read into resurrecting metadata or another device's health row.
func (db *DB) ControlBound(parent context.Context, req authority.ControlRequest) (protocol.CtrlResponse, error) {
	return db.controlAuthenticated(parent, req, true, false)
}

func (db *DB) ControlSession(parent context.Context, req authority.ControlRequest, channelBound bool) (protocol.CtrlResponse, error) {
	return db.controlAuthenticated(parent, req, channelBound, !channelBound)
}

func (db *DB) controlAuthenticated(parent context.Context, req authority.ControlRequest, requireChannel, legacySession bool) (protocol.CtrlResponse, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.CtrlResponse{}, err
	}
	defer tx.Rollback()
	p, err := accessPolicy(ctx, tx, req.Token)
	if err != nil {
		return protocol.CtrlResponse{}, err
	}
	if p.Generation != req.Generation || p.PublicKey != req.PublicKey || (requireChannel && !p.ChannelVerified) || (legacySession && (p.ChannelSeen || p.ChannelRequired)) {
		return protocol.CtrlResponse{}, authority.ErrDenied
	}
	resp := protocol.CtrlResponse{Status: p.Status, KickReason: p.Reason, BanReason: p.Reason, KickExpires: p.Expires, TelemetryMode: p.TelemetryMode}
	switch req.Request.Op {
	case "status":
		resp.OK = true
	case "health":
		if !validHealth(req.Request) || p.Status != "approved" || (p.KillSwitch && !p.KillAllowed) {
			return resp, authority.ErrDenied
		}
		r := req.Request
		if p.TelemetryMode == "minimal" {
			r.CPUPct, r.MemPct, r.TempC, r.LatencyMs, r.JitterMs, r.ProbeLossPct = 0, 0, 0, 0, 0, 0
			r.UptimeS = 0
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_health(token,version,os,arch,cpu_pct,mem_pct,temp_c,uptime_s,latency_ms,jitter_ms,probe_loss_pct,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,datetime('now')) ON CONFLICT(token) DO UPDATE SET version=excluded.version,os=excluded.os,arch=excluded.arch,cpu_pct=excluded.cpu_pct,mem_pct=excluded.mem_pct,temp_c=excluded.temp_c,uptime_s=excluded.uptime_s,latency_ms=excluded.latency_ms,jitter_ms=excluded.jitter_ms,probe_loss_pct=excluded.probe_loss_pct,at=excluded.at`, req.Token, r.Version, r.OS, r.Arch, r.CPUPct, r.MemPct, r.TempC, r.UptimeS, r.LatencyMs, r.JitterMs, r.ProbeLossPct); err != nil {
			return resp, err
		}
		resp.OK = true
	default:
		return resp, authority.ErrDenied
	}
	if req.Request.Op == "health" {
		if _, err := tx.ExecContext(ctx, `UPDATE device_health SET update_channel=?,update_state=?,channel_authentication=? WHERE token=?`, req.Request.UpdateChannel, req.Request.UpdateState, req.Request.ChannelAuthentication, req.Token); err != nil {
			return resp, err
		}
	}
	if p.Status == "approved" && (!p.KillSwitch || p.KillAllowed) {
		if _, err := tx.ExecContext(ctx, `UPDATE peers SET last_seen=datetime('now') WHERE token=? AND auth_epoch=? AND ssh_pubkey=?`, req.Token, req.Generation, req.PublicKey); err != nil {
			return resp, err
		}
	}
	return resp, tx.Commit()
}

func (db *DB) SetPeerIPBound(parent context.Context, req authority.PeerIPRequest) error {
	if len(req.IP) > 128 || net.ParseIP(req.IP) == nil {
		return authority.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := boundAuthorityPolicy(ctx, tx, req.Token, req.Generation, req.PublicKey)
	if err != nil {
		return err
	}
	if p.Status != "approved" || (p.KillSwitch && !p.KillAllowed) {
		return authority.ErrDenied
	}
	if p.TelemetryMode == "minimal" {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE peers SET last_ip=? WHERE token=? AND auth_epoch=? AND ssh_pubkey=?`, req.IP, req.Token, req.Generation, req.PublicKey); err != nil {
		return err
	}
	var recent bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM peer_ips WHERE token=? AND ip=? AND at>datetime('now','-1 minute'))`, req.Token, req.IP).Scan(&recent); err != nil {
		return err
	}
	if !recent {
		if _, err := tx.ExecContext(ctx, `INSERT INTO peer_ips(token,ip,at) VALUES(?,?,datetime('now'))`, req.Token, req.IP); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM peer_ips WHERE token=? AND rowid NOT IN (SELECT rowid FROM peer_ips WHERE token=? ORDER BY rowid DESC LIMIT 200)`, req.Token, req.Token); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) RecordVisitBound(parent context.Context, req authority.VisitRequest) error {
	if !validBlockDomain(req.Domain) {
		return authority.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := boundAuthorityPolicy(ctx, tx, req.Token, req.Generation, req.PublicKey)
	if err != nil {
		return err
	}
	if p.Status != "approved" || (p.KillSwitch && !p.KillAllowed) {
		return authority.ErrDenied
	}
	if p.TelemetryMode == "minimal" {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO visits(token,domain,hits,last_seen) VALUES(?,?,1,datetime('now')) ON CONFLICT(token,domain) DO UPDATE SET hits=hits+1,last_seen=datetime('now')`, req.Token, req.Domain); err != nil {
		return err
	}
	return tx.Commit()
}

// Node events are informational and rate-bounded. They cannot change bans,
// administrator credentials, approval or the node credential inventory.
func (db *DB) RecordNodeEvent(parent context.Context, node string, req authority.EventRequest) error {
	if !authority.ValidNodeID(node) || len(req.Kind) < 1 || len(req.Kind) > 64 || len(req.Detail) > 2048 || (req.Severity != "" && req.Severity != "info" && req.Severity != "warning" && req.Severity != "critical") {
		return authority.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	window := time.Now().Unix() / 60
	var oldWindow int64
	var count int
	err = tx.QueryRowContext(ctx, `SELECT window,count FROM authority_node_events WHERE node_id=?`, node).Scan(&oldWindow, &count)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if oldWindow != window {
		count = 0
	}
	if count >= 60 {
		return errors.New("node event capacity reached")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_node_events(node_id,window,count) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET window=excluded.window,count=excluded.count`, node, window, count+1); err != nil {
		return err
	}
	if req.Severity == "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('relay-node',?)`, node+": "+req.Kind+": "+req.Detail)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO alerts(severity,kind,message) VALUES(?,'relay-node',?)`, req.Severity, node+": "+req.Kind+": "+req.Detail)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)`); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) RecordNodeMetrics(parent context.Context, node string, snapshot metrics.Snapshot) error {
	if !authority.ValidNodeID(node) || len(snapshot.Version) > 64 || snapshot.UptimeS < 0 || snapshot.Goroutines < 0 || snapshot.ActiveSessions < 0 || snapshot.HeapMB < 0 || math.IsNaN(snapshot.HeapMB) || math.IsInf(snapshot.HeapMB, 0) {
		return authority.ErrDenied
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `INSERT INTO authority_node_metrics(node_id,snapshot,at) VALUES(?,?,datetime('now')) ON CONFLICT(node_id) DO UPDATE SET snapshot=excluded.snapshot,at=excluded.at`, node, string(raw))
	return err
}

func (db *DB) AuthoritySetting(parent context.Context, key string) (string, error) {
	if key != "sentinel_mode" {
		return "", authority.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "respond", nil
	}
	return value, err
}

var _ authority.Store = (*DB)(nil)
