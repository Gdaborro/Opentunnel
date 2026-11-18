package panel

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

func validBlockDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || domain != strings.ToLower(strings.TrimSpace(domain)) {
		return false
	}
	if net.ParseIP(domain) != nil {
		return true
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}

// BlocklistAction commits the selected mutation with its audit event. Invalid
// input, capacity errors and audit/SQL failure never partly clear policy.
func (db *DB) BlocklistAction(parent context.Context, method, domain, reason string, clearAll bool) error {
	if len(reason) > 500 || (clearAll && (method != "DELETE" || domain != "")) || (!clearAll && !validBlockDomain(domain)) {
		return errors.New("invalid blocklist action")
	}
	if method != "POST" && method != "DELETE" {
		return errors.New("unsupported blocklist action")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	detail := "blocklist cleared explicitly"
	if method == "POST" {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocklist WHERE domain!=?`, domain).Scan(&count); err != nil {
			return err
		}
		if count >= maxBlockRules-len(CategoryNames()) {
			return errors.New("blocklist capacity reached")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO blocklist(domain,reason) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET reason=excluded.reason`, domain, reason); err != nil {
			return err
		}
		detail = domain + " blocked"
	} else if clearAll {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist`); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist WHERE domain=?`, domain); err != nil {
			return err
		}
		detail = domain + " unblocked"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('blocklist',?)`, detail); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	db.invalidateBlockCache()
	return nil
}
