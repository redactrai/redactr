package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/redactrai/redactr/internal/admin"
	"github.com/redactrai/redactr/internal/certgen"
	"github.com/redactrai/redactr/internal/domain"
	"github.com/redactrai/redactr/internal/store"
)

type OnScanFunc func(report *store.ScanReport)

type Proxy struct {
	goproxy  *goproxy.ProxyHttpServer
	server   *http.Server
	listener net.Listener
	ca       *certgen.CA
	domains  *domain.Filter
	pipeline ScanPipeline
	bypass   *BypassMatcher
	onScan   OnScanFunc
	mu       sync.Mutex
	running  bool
}

func NewProxy(ca *certgen.CA, domains *domain.Filter, pipeline ScanPipeline, bypass *BypassMatcher, onScan OnScanFunc) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

	tlsCert, err := tls.X509KeyPair(
		caPEM(ca),
		caKeyPEM(ca),
	)
	if err != nil {
		return nil, err
	}

	goproxy.GoproxyCa = tlsCert
	tlsConfigFn := goproxy.TLSConfigFromCA(&tlsCert)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFn}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFn}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject}

	p := &Proxy{
		goproxy:  gp,
		ca:       ca,
		domains:  domains,
		pipeline: pipeline,
		bypass:   bypass,
		onScan:   onScan,
	}

	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if domains.IsBlocked(host) {
			return goproxy.RejectConnect, host
		}
		if domains.ShouldIntercept(host) {
			return goproxy.MitmConnect, host
		}
		return goproxy.OkConnect, host
	})

	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if !domains.ShouldIntercept(req.Host) {
			return req, nil
		}

		if p.bypass != nil {
			if matched, rule := p.bypass.Match(req.Method, req.URL.Path); matched {
				slog.Debug("bypass",
					"event", "bypass",
					"path", req.URL.Path,
					"method", req.Method,
					"rule", rule,
				)
				return req, nil
			}
		}

		if req.Body == nil {
			ctx.UserData = "passthrough"
			return req, nil
		}

		reqID := generateRequestID()

		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		start := time.Now()
		msg, err := ExtractLastUserMessage(body, req.Host)
		if err != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		redactedText, report, err := pipeline.ScanAndRedact(msg.Text)
		if err != nil {
			slog.Warn("scan failed, forwarding unredacted",
				"event", "scan_error",
				"request_id", reqID,
				"upstream", req.Host,
				"error", err.Error(),
				"action", "passthrough",
			)
			ctx.UserData = "passthrough"
			admin.RequestsTotal.WithLabelValues(req.Host, "passthrough").Inc()
			admin.ErrorsTotal.WithLabelValues("pipeline", "scan_error").Inc()
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		if redactedText != msg.Text {
			newBody, err := ReplaceLastUserMessage(body, msg, redactedText)
			if err != nil {
				slog.Warn("body rewrite failed",
					"event", "rewrite_error",
					"request_id", reqID,
					"upstream", req.Host,
					"error", err.Error(),
				)
				req.Body = io.NopCloser(bytes.NewReader(body))
				return req, nil
			}
			req.Body = io.NopCloser(bytes.NewReader(newBody))
			req.ContentLength = int64(len(newBody))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		totalMs := time.Since(start).Milliseconds()

		if report != nil {
			for _, f := range report.Findings {
				slog.Info("PII redacted",
					"event", "pii_redacted",
					"request_id", reqID,
					"entity_type", f.Label,
					"detection_layer", f.Layer,
					"confidence", f.Confidence,
					"upstream", req.Host,
				)
			}

			status := "full"
			allSkipped := true
			for _, lr := range report.LayerResults {
				if !lr.Skipped {
					allSkipped = false
				}
				if lr.Skipped {
					status = "partial"
				}
			}
			if allSkipped {
				status = "passthrough"
			}
			if status == "full" && len(report.Findings) == 0 {
				status = "clean"
			}
			ctx.UserData = status

			slog.Info("request processed",
				"event", "request_processed",
				"request_id", reqID,
				"entities_found", len(report.Findings),
				"entities_redacted", len(report.Findings),
				"detection_time_ms", report.TotalMs,
				"total_time_ms", totalMs,
				"status", status,
				"upstream", req.Host,
			)

			admin.RequestsTotal.WithLabelValues(req.Host, status).Inc()
			admin.RequestDuration.WithLabelValues(req.Host).Observe(float64(totalMs) / 1000.0)
			for _, f := range report.Findings {
				admin.EntitiesRedactedTotal.WithLabelValues(f.Label, f.Layer).Inc()
			}
			for _, lr := range report.LayerResults {
				admin.DetectionDuration.WithLabelValues(lr.Name).Observe(float64(lr.LatencyMs) / 1000.0)
				if lr.Skipped {
					admin.ErrorsTotal.WithLabelValues(lr.Name, "skipped").Inc()
				}
			}
		}

		if onScan := p.onScan; onScan != nil && report != nil {
			scanReport := &store.ScanReport{
				Timestamp: time.Now(),
				Provider:  req.Host,
				Source:    "proxy",
				LatencyMs: totalMs,
			}
			for _, f := range report.Findings {
				scanReport.Redactions = append(scanReport.Redactions, store.Redaction{
					Label:    f.Label,
					Original: f.Value,
					Start:    f.Start,
					End:      f.End,
					Layer:    f.Layer,
				})
			}
			for _, lr := range report.LayerResults {
				scanReport.Layers = append(scanReport.Layers, store.LayerResult{
					Name:          lr.Name,
					FindingsCount: lr.FindingsCount,
					LatencyMs:     lr.LatencyMs,
				})
			}
			onScan(scanReport)
		}

		return req, nil
	})

	gp.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && ctx.UserData != nil {
			if status, ok := ctx.UserData.(string); ok {
				resp.Header.Set("X-Redactr-Status", status)
			}
		}
		return resp
	})

	return p, nil
}

func (p *Proxy) Start(port int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var err error
	p.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", err
	}

	p.server = &http.Server{Handler: p.goproxy}
	p.running = true

	go p.server.Serve(p.listener)

	return p.listener.Addr().String(), nil
}

// StartTransparent binds an OS-assigned port (when port=0) for transparent
// (SNI-sniffing) connections from pf rdr redirected traffic. The returned
// address is the actual listener address (e.g. "127.0.0.1:58601") which
// the firewall controller uses when generating pf rules.
func (p *Proxy) StartTransparent(port int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	go p.startTransparent(l)
	return l.Addr().String(), nil
}

func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}
	p.running = false
	return p.server.Close()
}

func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func caPEM(ca *certgen.CA) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func caKeyPEM(ca *certgen.CA) []byte {
	keyDER, _ := x509.MarshalECPrivateKey(ca.Key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
