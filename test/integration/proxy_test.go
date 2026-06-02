//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/coordinator"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/proxy"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/contextgate"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/regex"
	"github.com/rakeshguha/redactr/internal/store"
)

func TestFullPipelineViaProxy(t *testing.T) {
	fakeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("user@secret.com")) {
			t.Error("PII leaked through proxy — email not redacted")
		}
		if !bytes.Contains(body, []byte("[REDACTED-EMAIL]")) {
			t.Error("expected redacted email in forwarded request")
		}
		w.Write([]byte(`{"id":"msg_123","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer fakeAPI.Close()

	dir := t.TempDir()
	ca, err := certgen.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	fakeHostPort := fakeAPI.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(fakeHostPort)
	df := domain.New([]string{host}, nil)

	regexLayer := regex.New(regex.DefaultPatterns(), nil)
	entropyLayer := entropy.New(4.5, 20)
	gateLayer := contextgate.New()
	pipeline := scanner.NewPipeline(regexLayer, entropyLayer, gateLayer)
	cache := scanner.NewCache(100)
	fb := fileblock.New([]string{".env"}, true)
	coord := coordinator.New(pipeline, cache, fb)

	var reports []*store.ScanReport
	onScan := func(r *store.ScanReport) { reports = append(reports, r) }

	p, err := proxy.NewProxy(ca, df, coord, nil, onScan)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	proxyAddr, err := p.Start(0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	reqBody := map[string]interface{}{
		"model": "claude-sonnet-4-20250514",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "my email is user@secret.com and key AKIAIOSFODNN7EXAMPLE"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := client.Post(fakeAPI.URL+"/v1/messages", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request via proxy: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	if len(reports) == 0 {
		t.Error("expected at least one scan report")
	}
}
