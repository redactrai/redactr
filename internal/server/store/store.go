// Package store is the control-plane server's embedded SQLite datastore:
// orgs, enrollment tokens, and devices.
package store

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"time"

	_ "modernc.org/sqlite"

	"github.com/redactrai/redactr/internal/control"
)

//go:embed schema.sql
var schema string

// ErrEnrollment is returned when an enrollment token is invalid (unknown,
// expired, revoked, or exhausted). Deliberately generic — no oracle on which.
var ErrEnrollment = errors.New("enrollment failed")

type Store struct{ db *sql.DB }

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Name       string     `json:"name"`
	Platform   string     `json:"platform"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Revoked    bool       `json:"revoked"`
}

// Open opens (creating if needed) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite is an embedded single-writer store; serialize all access through one
	// connection so the SELECT-then-UPDATE in EnrollDevice is race-free (no two
	// transactions can both pass the used_count check).
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Store) CreateOrg(name string) (Org, error) {
	o := Org{ID: newID(), Name: name, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)`, o.ID, o.Name, o.CreatedAt)
	return o, err
}

func (s *Store) ListOrgs() ([]Org, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at FROM orgs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetOrg(id string) (Org, error) {
	var o Org
	err := s.db.QueryRow(`SELECT id,name,created_at FROM orgs WHERE id=?`, id).Scan(&o.ID, &o.Name, &o.CreatedAt)
	return o, err
}

func (s *Store) CreateEnrollmentToken(tokenHash, orgID string, expiresAt time.Time, maxUses int, now time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_tokens(token_hash,org_id,expires_at,max_uses,used_count,revoked,created_at)
		 VALUES(?,?,?,?,0,0,?)`,
		tokenHash, orgID, expiresAt, maxUses, now)
	return err
}

// RevokeToken marks an enrollment token revoked so it can no longer enroll devices.
func (s *Store) RevokeToken(tokenHash string) error {
	_, err := s.db.Exec(`UPDATE enrollment_tokens SET revoked=1 WHERE token_hash=?`, tokenHash)
	return err
}

// EnrollDevice atomically validates the token (exists, not revoked, not expired,
// used_count < max_uses or max_uses == 0), inserts a device, and increments
// used_count. Returns ErrEnrollment if the token is invalid.
func (s *Store) EnrollDevice(tokenHash, name, platform string, now time.Time) (Device, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()

	var orgID string
	var expiresAt time.Time
	var maxUses, usedCount, revoked int
	err = tx.QueryRow(
		`SELECT org_id,expires_at,max_uses,used_count,revoked FROM enrollment_tokens WHERE token_hash=?`,
		tokenHash).Scan(&orgID, &expiresAt, &maxUses, &usedCount, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrEnrollment
	}
	if err != nil {
		return Device{}, err
	}
	if revoked != 0 || now.After(expiresAt) || (maxUses != 0 && usedCount >= maxUses) {
		return Device{}, ErrEnrollment
	}

	d := Device{ID: newID(), OrgID: orgID, Name: name, Platform: platform, EnrolledAt: now}
	if _, err := tx.Exec(
		`INSERT INTO devices(id,org_id,name,platform,enrolled_at,revoked) VALUES(?,?,?,?,?,0)`,
		d.ID, d.OrgID, d.Name, d.Platform, d.EnrolledAt); err != nil {
		return Device{}, err
	}
	if _, err := tx.Exec(`UPDATE enrollment_tokens SET used_count=used_count+1 WHERE token_hash=?`, tokenHash); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return d, nil
}

func (s *Store) GetDevice(id string) (Device, error) {
	var d Device
	var last sql.NullTime
	var revoked int
	err := s.db.QueryRow(
		`SELECT id,org_id,name,platform,enrolled_at,last_seen_at,revoked FROM devices WHERE id=?`, id).
		Scan(&d.ID, &d.OrgID, &d.Name, &d.Platform, &d.EnrolledAt, &last, &revoked)
	if err != nil {
		return Device{}, err
	}
	if last.Valid {
		d.LastSeenAt = &last.Time
	}
	d.Revoked = revoked != 0
	return d, nil
}

func (s *Store) ListDevices(orgID string) ([]Device, error) {
	rows, err := s.db.Query(
		`SELECT id,org_id,name,platform,enrolled_at,last_seen_at,revoked FROM devices WHERE org_id=? ORDER BY enrolled_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var last sql.NullTime
		var revoked int
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Name, &d.Platform, &d.EnrolledAt, &last, &revoked); err != nil {
			return nil, err
		}
		if last.Valid {
			d.LastSeenAt = &last.Time
		}
		d.Revoked = revoked != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDevice(id string) error {
	_, err := s.db.Exec(`UPDATE devices SET revoked=1 WHERE id=?`, id)
	return err
}

func (s *Store) TouchDevice(id string, t time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen_at=? WHERE id=?`, t, id)
	return err
}

// seedPolicyJSON is served when an org has no policy set.
const seedPolicyJSON = `{"image":"redactr-base:local","mountMode":"bind","denylist":[]}`

// GetPolicy returns the org's policy bundle JSON and version. If none is set,
// it returns the seed bundle with version 0.
func (s *Store) GetPolicy(orgID string) ([]byte, int, error) {
	var raw string
	var version int
	err := s.db.QueryRow(`SELECT bundle_json,version FROM policies WHERE org_id=?`, orgID).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return []byte(seedPolicyJSON), 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return []byte(raw), version, nil
}

// Event is a stored monitoring event (metadata only).
type Event struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	DeviceID        string    `json:"device_id"`
	Tool            string    `json:"tool"`
	Verdict         string    `json:"verdict"`
	Reason          string    `json:"reason"`
	DirectConnCount int       `json:"direct_conn_count"`
	ObservedAt      time.Time `json:"observed_at"`
	ReceivedAt      time.Time `json:"received_at"`
}

// InsertEvents writes a batch of monitoring events for a device in one tx.
func (s *Store) InsertEvents(orgID, deviceID string, evs []control.MonitorEvent, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range evs {
		if _, err := tx.Exec(
			`INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			newID(), orgID, deviceID, e.Tool, e.Verdict, e.Reason, e.DirectConnCount, e.ObservedAt, receivedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListEvents returns the most recent events for an org (newest first).
func (s *Store) ListEvents(orgID string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at
		 FROM events WHERE org_id=? ORDER BY received_at DESC LIMIT ?`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.OrgID, &e.DeviceID, &e.Tool, &e.Verdict, &e.Reason, &e.DirectConnCount, &e.ObservedAt, &e.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByVerdict returns per-verdict counts for events received since `since`.
func (s *Store) CountByVerdict(orgID string, since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT verdict, COUNT(*) FROM events WHERE org_id=? AND received_at>=? GROUP BY verdict`, orgID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}

// Image is a stored built-image record.
type Image struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Tag       string    `json:"tag"`
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// InsertImage records a new image in 'building' status and returns its id.
func (s *Store) InsertImage(orgID, tag string) (string, error) {
	id := newID()
	_, err := s.db.Exec(
		`INSERT INTO images(id,org_id,tag,status,created_at) VALUES(?,?,?,?,?)`,
		id, orgID, tag, "building", time.Now().UTC())
	return id, err
}

// SetImageResult updates an image row after a build attempt.
func (s *Store) SetImageResult(id, ref, digest, status string) error {
	_, err := s.db.Exec(`UPDATE images SET ref=?, digest=?, status=? WHERE id=?`, ref, digest, status, id)
	return err
}

// ListImages returns an org's images, newest first.
func (s *Store) ListImages(orgID string) ([]Image, error) {
	rows, err := s.db.Query(
		`SELECT id,org_id,tag,ref,digest,status,created_at FROM images WHERE org_id=? ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Image{}
	for rows.Next() {
		var im Image
		if err := rows.Scan(&im.ID, &im.OrgID, &im.Tag, &im.Ref, &im.Digest, &im.Status, &im.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// PutPolicy upserts the org's policy bundle and bumps its version (1 on first set).
func (s *Store) PutPolicy(orgID string, bundleJSON []byte) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow(`SELECT version FROM policies WHERE org_id=?`, orgID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		version = 0
	} else if err != nil {
		return 0, err
	}
	version++
	if _, err := tx.Exec(
		`INSERT INTO policies(org_id,bundle_json,version,updated_at) VALUES(?,?,?,?)
		 ON CONFLICT(org_id) DO UPDATE SET bundle_json=excluded.bundle_json, version=excluded.version, updated_at=excluded.updated_at`,
		orgID, string(bundleJSON), version, time.Now().UTC()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}
