//go:build !darwin

package sessions

import (
	"errors"
	"time"
)

type rawProc struct {
	PID       int
	PPID      int
	User      string
	Command   string
	StartedAt time.Time
}

var errUnsupported = errors.New("session discovery is currently only implemented for macOS")

func scanProcesses() ([]rawProc, error)            { return nil, errUnsupported }
func processEnv(pid int) (map[string]string, error) { return nil, errUnsupported }
func processConnections(pid int) ([]string, error)  { return nil, errUnsupported }
func lookupHost(h string) ([]string, error)         { return nil, errUnsupported }

func Stop(pid int) error                       { return errUnsupported }
func LaunchProtectedShell(redactrBin string) error { return errUnsupported }

func PlatformSupported() bool { return false }
