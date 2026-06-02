package proxy

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// startTransparent runs the SNI-sniffing listener loop on l. For every
// accepted connection it reads the TLS ClientHello, extracts the SNI,
// and (if SNI matches an intercepted domain) splices the connection
// into goproxy as if a CONNECT had been issued.
//
// Connections without SNI, or whose SNI doesn't match any intercepted
// domain, are closed. We don't transparently bridge to the original
// destination because pf strips it on macOS — bridging would require
// SO_ORIGINAL_DST which doesn't exist on Darwin.
func (p *Proxy) startTransparent(l net.Listener) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("transparent accept", "error", err)
			continue
		}
		go p.handleTransparent(c)
	}
}

func (p *Proxy) handleTransparent(c net.Conn) {
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.Close()
		return
	}

	// Peek the first TLS record without consuming it. We use a buffered
	// reader and Peek so the bytes can be replayed to goproxy.
	br := bufio.NewReaderSize(c, 16*1024)
	header, err := br.Peek(5)
	if err != nil {
		slog.Debug("transparent peek header", "error", err)
		c.Close()
		return
	}
	if header[0] != 0x16 {
		slog.Debug("transparent: not a TLS handshake")
		c.Close()
		return
	}
	recLen := int(header[3])<<8 | int(header[4])
	if recLen <= 0 || recLen > 16*1024 {
		slog.Debug("transparent: bogus record length", "len", recLen)
		c.Close()
		return
	}
	hello, err := br.Peek(5 + recLen)
	if err != nil {
		slog.Debug("transparent peek body", "error", err)
		c.Close()
		return
	}
	host, err := parseSNI(hello)
	if err != nil {
		slog.Debug("transparent SNI parse", "error", err)
		c.Close()
		return
	}
	if !p.domains.ShouldIntercept(host) {
		slog.Debug("transparent: SNI not in intercept list", "host", host)
		c.Close()
		return
	}

	// Clear deadline; goproxy manages its own.
	_ = c.SetReadDeadline(time.Time{})

	// Construct a synthetic CONNECT request and a replay-buffered conn so
	// the full TLS handshake is visible to goproxy.
	connectReq := "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n\r\n"
	wrapped := &replayConn{
		Conn:  c,
		extra: io.MultiReader(strings.NewReader(connectReq), br),
	}
	p.serveConn(wrapped)
}

// replayConn wraps a net.Conn so that Read returns from `extra` first
// (the synthetic CONNECT followed by the buffered ClientHello), then
// falls through to the underlying Conn.
type replayConn struct {
	net.Conn
	mu    sync.Mutex
	extra io.Reader
}

func (r *replayConn) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.extra != nil {
		n, err := r.extra.Read(b)
		if err == io.EOF {
			r.extra = nil
			err = nil
		}
		if n > 0 {
			return n, err
		}
		r.extra = nil
	}
	return r.Conn.Read(b)
}

// serveConn hands a single connection to goproxy by constructing a
// one-shot listener that returns this connection once.
func (p *Proxy) serveConn(c net.Conn) {
	listener := &oneShotListener{conn: c, addr: c.LocalAddr()}
	srv := &http.Server{Handler: p.goproxy}
	_ = srv.Serve(listener)
}

type oneShotListener struct {
	conn net.Conn
	addr net.Addr
	done bool
	mu   sync.Mutex
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.addr }
