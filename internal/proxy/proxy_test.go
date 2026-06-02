package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/scanner"
)

type noopPipeline struct{}

func (n *noopPipeline) ScanAndRedact(text string) (string, *scanner.PipelineReport, error) {
	return text, &scanner.PipelineReport{}, nil
}

func TestProxyStartStop(t *testing.T) {
	dir := t.TempDir()
	ca, err := certgen.GenerateCA(
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if err != nil {
		t.Fatalf("CA error: %v", err)
	}

	df := domain.New([]string{"api.anthropic.com"}, nil)
	p, err := NewProxy(ca, df, &noopPipeline{}, nil, nil)
	if err != nil {
		t.Fatalf("NewProxy error: %v", err)
	}

	addr, err := p.Start(0)
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if addr == "" {
		t.Error("expected non-empty address")
	}

	err = p.Stop()
	if err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

func TestProxyForwardsNonInterceptedTraffic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	ca, _ := certgen.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	df := domain.New([]string{"api.anthropic.com"}, nil)
	p, _ := NewProxy(ca, df, &noopPipeline{}, nil, nil)
	addr, _ := p.Start(0)
	defer p.Stop()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", string(body))
	}
}
