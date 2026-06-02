package scanner_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/gliner"
	"github.com/rakeshguha/redactr/internal/scanner/presidio"
)

// TestPresidioConcurrentScanReconfigure exercises the production scenario
// where the dashboard's PUT /api/rules triggers Reconfigure on one
// goroutine while proxy traffic is being scanned on others. Run with
// `go test -race ./internal/scanner/...` to confirm there is no data
// race on s.patterns or s.enabled.
func TestPresidioConcurrentScanReconfigure(t *testing.T) {
	s := presidio.New()
	const text = "hello jane@example.com and 4242 4242 4242 4242 cvv: 123 credit"
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Scanner goroutines.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = s.Scan(text)
				}
			}
		}()
	}

	// Reconfigure flipper.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var n atomic.Uint32
		for {
			select {
			case <-stop:
				return
			default:
				flip := n.Add(1)%2 == 0
				s.Reconfigure(func(string) bool { return flip })
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestGLiNERConcurrentScanReconfigure(t *testing.T) {
	c := gliner.New("http://127.0.0.1:0") // not Ready, so Scan returns empty
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = c.Scan("text doesn't matter when sidecar is unready")
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var n atomic.Uint32
		for {
			select {
			case <-stop:
				return
			default:
				flip := n.Add(1)%2 == 0
				c.Reconfigure(func(string) bool { return flip })
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestEntropyConcurrentScanReconfigure(t *testing.T) {
	s := entropy.New(4.5, 20)
	const text = "api_key = aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0 plus other content"
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = s.Scan(text)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var n atomic.Uint32
		for {
			select {
			case <-stop:
				return
			default:
				flip := n.Add(1)%2 == 0
				s.SetEnabled(flip, !flip)
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestFileblockConcurrentReconfigure(t *testing.T) {
	fb := fileblock.New([]string{".env", ".pem"}, true)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = fb.IsBlockedFile("/etc/secret.env")
					_ = fb.IsBlockedContent("KEY=foo\nSECRET=bar\nTOKEN=baz\n")
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var n atomic.Uint32
		for {
			select {
			case <-stop:
				return
			default:
				flip := n.Add(1)%2 == 0
				if flip {
					fb.Reconfigure([]string{".env", ".pem"}, true)
				} else {
					fb.Reconfigure([]string{".key"}, false)
				}
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}
