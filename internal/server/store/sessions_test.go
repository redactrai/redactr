package store

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	s := openTest(t)

	sess, err := s.CreateSession("alice@example.com", "admin", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID should not be empty")
	}
	if sess.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want %q", sess.Subject, "alice@example.com")
	}
	if sess.Role != "admin" {
		t.Errorf("Role = %q, want %q", sess.Role, "admin")
	}
	if sess.ExpiresAt.Before(sess.CreatedAt) {
		t.Errorf("ExpiresAt %v before CreatedAt %v", sess.ExpiresAt, sess.CreatedAt)
	}

	// Lookup should find it
	got, err := s.LookupSession(sess.ID)
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if got.Subject != sess.Subject || got.Role != sess.Role || got.ID != sess.ID {
		t.Errorf("LookupSession mismatch: got %+v want %+v", got, sess)
	}

	// Delete it
	if err := s.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Should be gone
	_, err = s.LookupSession(sess.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("after delete LookupSession err = %v, want ErrSessionNotFound", err)
	}
}

func TestExpiredSessionRejectedAndSwept(t *testing.T) {
	s := openTest(t)

	// Fix the clock to a known time
	base := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return base }

	sess, err := s.CreateSession("bob@example.com", "admin", time.Second)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Advance clock past expiry
	s.now = func() time.Time { return base.Add(2 * time.Second) }

	_, err = s.LookupSession(sess.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("LookupSession on expired session err = %v, want ErrSessionExpired", err)
	}

	n, err := s.SweepExpiredSessions()
	if err != nil {
		t.Fatalf("SweepExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Errorf("SweepExpiredSessions = %d, want 1", n)
	}

	// Session should now be gone
	_, err = s.LookupSession(sess.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("after sweep LookupSession err = %v, want ErrSessionNotFound", err)
	}
}

func TestExpiredSessionExactBoundary(t *testing.T) {
	s := openTest(t)

	// Fix the clock to a known time.
	base := time.Unix(1_700_000_000, 0).UTC()
	ttl := time.Hour
	s.now = func() time.Time { return base }

	sess, err := s.CreateSession("carol@example.com", "admin", ttl)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Advance clock to exactly expires_at (== CreatedAt + ttl).
	// Semantics are: "not after" == expired, so this should return ErrSessionExpired.
	s.now = func() time.Time { return sess.ExpiresAt }

	_, err = s.LookupSession(sess.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("LookupSession at exact expiry boundary: got %v, want ErrSessionExpired", err)
	}
}

func TestAdminAllowlist(t *testing.T) {
	s := openTest(t)

	if err := s.AddAdmin("A@X.com", "superadmin"); err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}

	// Case-insensitive lookup
	ok, err := s.IsAdmin("a@x.com")
	if err != nil {
		t.Fatalf("IsAdmin: %v", err)
	}
	if !ok {
		t.Error("IsAdmin(a@x.com) = false, want true")
	}

	// ListAdmins should contain the lowercased email
	list, err := s.ListAdmins()
	if err != nil {
		t.Fatalf("ListAdmins: %v", err)
	}
	found := false
	for _, e := range list {
		if e == "a@x.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("ListAdmins = %v, want to contain %q", list, "a@x.com")
	}

	// Remove and verify gone
	if err := s.RemoveAdmin("a@x.com"); err != nil {
		t.Fatalf("RemoveAdmin: %v", err)
	}
	ok, err = s.IsAdmin("a@x.com")
	if err != nil {
		t.Fatalf("IsAdmin after remove: %v", err)
	}
	if ok {
		t.Error("IsAdmin after RemoveAdmin = true, want false")
	}
}
