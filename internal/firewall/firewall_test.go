package firewall

import (
	"runtime"
	"testing"
)

func TestNewReturnsCorrectPlatform(t *testing.T) {
	mgr, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	switch runtime.GOOS {
	case "darwin":
		if _, ok := mgr.(*darwinFirewall); !ok {
			t.Error("expected darwinFirewall on macOS")
		}
	case "linux":
		if _, ok := mgr.(*linuxFirewall); !ok {
			t.Error("expected linuxFirewall on Linux")
		}
	case "windows":
		if _, ok := mgr.(*windowsFirewall); !ok {
			t.Error("expected windowsFirewall on Windows")
		}
	}
}
