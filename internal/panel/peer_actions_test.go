package panel

import "testing"

func TestKickCannotReviveUnapprovedIdentity(t *testing.T) {
	for _, state := range []string{"pending", "expired", "banned"} {
		t.Run(state, func(t *testing.T) {
			db := newTestDB(t)
			token := accessPeer(t, db)
			db.Exec(`UPDATE peers SET status=? WHERE token=?`, state, token)
			if err := db.PeerStateAction(token, "kick", "fixture", ""); err == nil {
				t.Fatal("kick promoted an unapproved device")
			}
			var got string
			_ = db.QueryRow(`SELECT status FROM peers WHERE token=?`, token).Scan(&got)
			if got != state {
				t.Fatal("invalid state transition persisted")
			}
		})
	}
}
func TestDeletingBannedPeerDoesNotRemoveIdentityBan(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	if err := db.PeerStateAction(token, "ban", "fixture", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.PeerStateAction(token, "delete", "", ""); err != nil {
		t.Fatal(err)
	}
	if !db.IdentityBanned("fixture", "") {
		t.Fatal("deletion silently unbanned identity")
	}
}
