package client

import (
	"sync"
	"time"

	"opentunnel/internal/version"
)

type UpdateStatus struct {
	State     string
	Tag       string
	ExpiresAt int64
}

var updateStatusMu sync.Mutex
var updateStatus = UpdateStatus{State: "not checked"}

func setUpdateStatus(state, tag string, expires int64) {
	updateStatusMu.Lock()
	updateStatus = UpdateStatus{State: state, Tag: tag, ExpiresAt: expires}
	updateStatusMu.Unlock()
}
func CurrentUpdateStatus() UpdateStatus {
	if version.LocalPreview != "" {
		return UpdateStatus{State: "unreleased local preview; automatic updates disabled"}
	}
	updateStatusMu.Lock()
	defer updateStatusMu.Unlock()
	status := updateStatus
	if status.ExpiresAt > 0 && status.ExpiresAt <= time.Now().Unix() {
		status.State = "signed update metadata expired; freshness not verified"
	}
	return status
}
