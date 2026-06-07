package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// ErrSessionNotFound is returned by LookupSession when the session ID is unknown.
var ErrSessionNotFound = errors.New("session not found")

// ErrSessionExpired is returned by LookupSession when the session exists but has expired.
var ErrSessionExpired = errors.New("session expired")

// Session is a server-side session record.
type Session struct {
	ID        string
	Subject   string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// newSessionID generates a 256-bit random ID encoded as base64url (no padding).
func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// CreateSession creates a new session with the given subject, role, and TTL.
func (s *Store) CreateSession(subject, role string, ttl time.Duration) (Session, error) {
	id, err := newSessionID()
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	sess := Session{
		ID:        id,
		Subject:   subject,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	_, err = s.db.Exec(
		`INSERT INTO sessions(id,subject,role,created_at,expires_at) VALUES(?,?,?,?,?)`,
		sess.ID, sess.Subject, sess.Role, sess.CreatedAt, sess.ExpiresAt,
	)
	return sess, err
}

// LookupSession returns the session for the given ID.
// Returns ErrSessionNotFound if the ID is unknown, ErrSessionExpired if it exists but is past its expiry.
func (s *Store) LookupSession(id string) (Session, error) {
	var sess Session
	err := s.db.QueryRow(
		`SELECT id,subject,role,created_at,expires_at FROM sessions WHERE id=?`, id,
	).Scan(&sess.ID, &sess.Subject, &sess.Role, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, err
	}
	if !sess.ExpiresAt.After(s.now()) {
		return Session{}, ErrSessionExpired
	}
	return sess, nil
}

// DeleteSession removes the session with the given ID (no error if absent).
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

// SweepExpiredSessions deletes all sessions whose expires_at is <= now.
// Returns the number of rows deleted.
func (s *Store) SweepExpiredSessions() (int, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, s.now())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// AddAdmin adds an email to the admin allowlist, lowercasing it.
func (s *Store) AddAdmin(email, addedBy string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO admins(email,added_by,created_at) VALUES(?,?,?)`,
		strings.ToLower(email), addedBy, s.now(),
	)
	return err
}

// RemoveAdmin removes an email from the admin allowlist.
func (s *Store) RemoveAdmin(email string) error {
	_, err := s.db.Exec(`DELETE FROM admins WHERE email=?`, strings.ToLower(email))
	return err
}

// IsAdmin returns true if the given email (case-insensitive) is in the admin allowlist.
func (s *Store) IsAdmin(email string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM admins WHERE email=?`, strings.ToLower(email),
	).Scan(&count)
	return count > 0, err
}

// ListAdmins returns all admin emails in the allowlist.
func (s *Store) ListAdmins() ([]string, error) {
	rows, err := s.db.Query(`SELECT email FROM admins ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
