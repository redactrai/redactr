package api

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/redactrai/redactr/internal/config"
	"github.com/redactrai/redactr/internal/coordinator"
	"github.com/redactrai/redactr/internal/firewall"
	"github.com/redactrai/redactr/internal/licensing"
	"github.com/redactrai/redactr/internal/sessions"
	"github.com/redactrai/redactr/internal/store"
)

type ProxyController interface {
	Start(port int) (string, error)
	Stop() error
	Addr() string
}

type Server struct {
	cfgMgr          *config.Manager
	store           *store.Store
	proxy           ProxyController
	coordinator     *coordinator.Coordinator
	hub             *Hub
	sessions        *sessions.Lister
	license         *licensing.Manager
	redactrBinary   string
	firewall        *firewall.Controller
	transparentAddr string
	mux             *http.ServeMux
	listener        net.Listener
	mu              sync.Mutex
}

func NewServer(cfgMgr *config.Manager, store *store.Store, proxy ProxyController, coord *coordinator.Coordinator, hub *Hub) *Server {
	s := &Server{
		cfgMgr:      cfgMgr,
		store:       store,
		proxy:       proxy,
		coordinator: coord,
		hub:         hub,
		mux:         http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// SetFirewall attaches a firewall Controller and the transparent
// listener address used when generating pf rules. Called from main
// during startup before Start.
func (s *Server) SetFirewall(c *firewall.Controller, transparentAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firewall = c
	s.transparentAddr = transparentAddr
}

// SetSessions attaches a sessions lister so the dashboard can show running
// AI-tool processes and their routing posture.
func (s *Server) SetSessions(l *sessions.Lister) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = l
}

// SetLicense attaches a license manager so the API can report license status.
func (s *Server) SetLicense(l *licensing.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.license = l
}

// SetRedactrBinary records the absolute path to the running redactr binary so
// the API can launch protected shells with it.
func (s *Server) SetRedactrBinary(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redactrBinary = path
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Start(port int) (string, error) {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", err
	}
	go http.Serve(s.listener, s.mux)
	return s.listener.Addr().String(), nil
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
