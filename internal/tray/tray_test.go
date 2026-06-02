package tray

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/control"
)

func TestTrayStateGreenWhenProxyLive(t *testing.T) {
	s := TrayState(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}}, true)
	if s.Color != "green" {
		t.Errorf("Color = %q, want green", s.Color)
	}
	if s.ProxyLabel != "Proxy: Enabled" {
		t.Errorf("ProxyLabel = %q", s.ProxyLabel)
	}
}

func TestTrayStateRedWhenProxyDisabled(t *testing.T) {
	s := TrayState(control.Status{Proxy: control.ProxyStatus{Enabled: false}}, true)
	if s.Color != "red" {
		t.Errorf("Color = %q, want red", s.Color)
	}
	if s.ProxyLabel != "Proxy: Disabled" {
		t.Errorf("ProxyLabel = %q, want Proxy: Disabled", s.ProxyLabel)
	}
}

func TestTrayStateRedWhenDaemonDown(t *testing.T) {
	s := TrayState(control.Status{}, false)
	if s.Color != "red" || s.ProxyLabel != "Daemon: Down" {
		t.Errorf("got %+v, want red/Daemon: Down", s)
	}
}
