package daemon

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func TestControlSocketStatusAndPolicy(t *testing.T) {
	base := t.TempDir()
	d, err := Build(Options{BaseDir: base, Ephemeral: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Stop()

	client := socketHTTPClient(filepath.Join(base, "state", "redactr.sock"))

	resp, err := client.Get("http://unix/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/status code = %d", resp.StatusCode)
	}
	var st map[string]any
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if _, ok := st["proxy"]; !ok {
		t.Errorf("/status missing proxy field: %v", st)
	}

	resp2, err := client.Get("http://unix/launch-policy?tool=claude")
	if err != nil {
		t.Fatalf("GET /launch-policy: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("/launch-policy code = %d", resp2.StatusCode)
	}
	var li map[string]any
	json.NewDecoder(resp2.Body).Decode(&li)
	resp2.Body.Close()
	if li["image"] != "redactr-base:local" {
		t.Errorf("/launch-policy image = %v, want redactr-base:local", li["image"])
	}
}

// socketHTTPClient returns an *http.Client that dials the given unix socket.
func socketHTTPClient(sockPath string) *http.Client {
	return newUnixClient(sockPath) // defined in socket.go
}
