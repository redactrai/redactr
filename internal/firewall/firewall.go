package firewall

import (
	"errors"
	"fmt"
	"runtime"
)

type Manager interface {
	BlockDirect(domains []string, proxyPort int) error
	Unblock() error
	Status() ([]Rule, error)
	Cleanup() error

	// Redirect installs OS-level rules that redirect TCP:443 traffic to the
	// listed IPs into the local transparent listener. Idempotent: replaces
	// any prior rules in the redactr anchor.
	Redirect(ips []string, transparentPort int) error

	// Unredirect removes all rules installed by Redirect.
	Unredirect() error

	// IsActive reports whether redirect rules are currently installed.
	IsActive() (bool, error)
}

// ErrNotImplemented is returned by platforms that don't yet support
// transparent routing.
var ErrNotImplemented = errors.New("transparent routing not implemented on this platform")

type Rule struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Active bool   `json:"active"`
}

func New() (Manager, error) {
	switch runtime.GOOS {
	case "darwin":
		return &darwinFirewall{}, nil
	case "linux":
		return &linuxFirewall{}, nil
	case "windows":
		return &windowsFirewall{}, nil
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
