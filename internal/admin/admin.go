package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type LayerStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type LayerChecker interface {
	Name() string
	Ready() bool
}

type Server struct {
	mux      *http.ServeMux
	listener net.Listener
	layers   []LayerChecker
}

func NewServer(layers []LayerChecker) *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		layers: layers,
	}
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.Handle("GET /metrics", promhttp.Handler())
	return s
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	models := map[string]string{}
	healthy := true

	for _, l := range s.layers {
		if l.Ready() {
			models[l.Name()] = "ready"
		} else {
			models[l.Name()] = "not ready"
			healthy = false
		}
	}

	status := "healthy"
	code := http.StatusOK
	if !healthy {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"models": models,
	})
}
