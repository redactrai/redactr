//go:build windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

// Win32 process-creation flags (see CreateProcess docs) — detach the daemon
// from the launching console (and suppress a console window) so it survives the
// CLI exiting and never flashes a window when launched from a GUI.
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
	createNoWindow        = 0x08000000
)

// spawnDaemon launches the current binary as a detached background daemon.
func spawnDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self) // no subcommand => daemon.Run
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | createNewProcessGroup | createNoWindow}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start()
}
