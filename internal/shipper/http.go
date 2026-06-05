package shipper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
)

// HTTPPoster delivers batches to POST /v1/ingest using the saved enrollment.
type HTTPPoster struct {
	baseDir string
	client  *http.Client
}

// NewHTTPPoster builds a poster reading enrollment from baseDir on each call,
// so a device that enrolls while the daemon runs is picked up without restart.
func NewHTTPPoster(baseDir string) *HTTPPoster {
	return &HTTPPoster{baseDir: baseDir, client: &http.Client{Timeout: 15 * time.Second}}
}

func (p *HTTPPoster) Post(ctx context.Context, records []control.IngestRecord) error {
	enr, err := enrollment.Load(p.baseDir)
	if err != nil {
		return err // not enrolled / unreadable: retain records and retry later
	}
	body, err := json.Marshal(control.IngestRequest{Records: records})
	if err != nil {
		return err
	}
	url := strings.TrimRight(enr.ServerURL, "/") + "/v1/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+enr.DeviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("ingest failed: %d", resp.StatusCode)
	}
	return nil
}
