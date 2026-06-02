package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/rakeshguha/redactr/internal/server/store"
)

// HashToken returns the hex SHA-256 of a raw enrollment token (what the DB stores).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type EnrollInput struct {
	EnrollmentToken string
	DeviceName      string
	Platform        string
}

type EnrollResult struct {
	DeviceID string
	OrgID    string
	Token    string
}

// Enroll validates the enrollment token (via the store's transactional check),
// creates the device, and issues a signed device bearer token.
func Enroll(st *store.Store, signer *Signer, in EnrollInput, now time.Time) (EnrollResult, error) {
	dev, err := st.EnrollDevice(HashToken(in.EnrollmentToken), in.DeviceName, in.Platform, now)
	if err != nil {
		return EnrollResult{}, err // store.ErrEnrollment on invalid token
	}
	tok, err := signer.Sign(Claims{DeviceID: dev.ID, OrgID: dev.OrgID, IssuedAt: now.Unix()})
	if err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{DeviceID: dev.ID, OrgID: dev.OrgID, Token: tok}, nil
}
