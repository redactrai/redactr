// Package policysync pulls the signed policy bundle from the control-plane
// server, verifies it against the stored server public key, and refreshes the
// local policy cache. Every failure mode is fail-open: the cached policy is kept.
package policysync

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/enrollment"
	"github.com/rakeshguha/redactr/internal/policy"
	"github.com/rakeshguha/redactr/internal/signing"
)

func etagPath(baseDir string) string { return filepath.Join(baseDir, "cache", "policy.etag") }

// Sync fetches and verifies the server policy, refreshing the local cache.
// Returns nil (no-op) if the device is not enrolled. On any network/verify
// failure it returns the error but leaves the cached policy untouched.
func Sync(baseDir string) error {
	if !enrollment.Exists(baseDir) {
		return nil
	}
	enr, err := enrollment.Load(baseDir)
	if err != nil {
		return err
	}
	pub, err := signing.ParsePublicKeyPEM(enr.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("bad stored server key: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(enr.ServerURL, "/")+"/v1/policy", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+enr.DeviceToken)
	if etag, _ := os.ReadFile(etagPath(baseDir)); len(etag) > 0 {
		req.Header.Set("If-None-Match", string(etag))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy fetch failed: %d", resp.StatusCode)
	}

	var sp control.SignedPolicy
	if err := json.NewDecoder(resp.Body).Decode(&sp); err != nil {
		return err
	}
	bundleJSON, err := base64.RawURLEncoding.DecodeString(sp.Bundle)
	if err != nil {
		return err
	}
	if err := signing.Verify(pub, bundleJSON, sp.Signature); err != nil {
		return fmt.Errorf("policy signature rejected: %w", err)
	}

	var b control.PolicyBundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return err
	}
	if err := policy.Save(baseDir, policy.Policy{
		Image: b.Image, MountMode: b.MountMode, Denylist: b.Denylist, Version: b.Version, FetchedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.MkdirAll(filepath.Dir(etagPath(baseDir)), 0o755)
		_ = os.WriteFile(etagPath(baseDir), []byte(etag), 0o600)
	}
	return nil
}
