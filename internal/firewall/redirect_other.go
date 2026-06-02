//go:build !darwin

package firewall

// SetCAPath is a no-op on non-darwin platforms. On macOS this stores the CA
// certificate path for the pf redirect machinery.
func SetCAPath(_ string) {}

// darwinFirewall is always compiled (darwin.go has no build tag), but its real
// Redirect/Unredirect/IsActive live in redirect_darwin.go (//go:build darwin).
// These stubs complete darwinFirewall's Manager implementation on non-darwin,
// where it is never instantiated (New() returns linux/windowsFirewall there).
func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *darwinFirewall) Unredirect() error                                { return ErrNotImplemented }
func (f *darwinFirewall) IsActive() (bool, error)                          { return false, nil }
