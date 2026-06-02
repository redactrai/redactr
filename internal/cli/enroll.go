package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/enrollment"
)

// RunEnroll enrolls this device with the control-plane server and stores the
// resulting device token + server public key under baseDir.
func RunEnroll(baseDir, serverURL, enrollToken string) error {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	body, _ := json.Marshal(map[string]string{
		"enrollment_token": enrollToken,
		"device_name":      host,
		"platform":         runtime.GOOS,
	})
	url := strings.TrimRight(serverURL, "/") + "/v1/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment failed (server returned %d)", resp.StatusCode)
	}
	var raw map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	if raw["token"] == "" {
		return fmt.Errorf("enrollment response missing token")
	}
	if raw["server_public_key"] == "" {
		return fmt.Errorf("enrollment response missing server_public_key")
	}
	if err := enrollment.Save(baseDir, enrollment.Enrollment{
		ServerURL:       strings.TrimRight(serverURL, "/"),
		DeviceToken:     raw["token"],
		ServerPublicKey: raw["server_public_key"],
		DeviceID:        raw["device_id"],
		OrgID:           raw["org_id"],
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "enrolled device %s in org %s\n", raw["device_id"], raw["org_id"])
	return nil
}
