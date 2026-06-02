//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnDaemon launches the current binary as a detached background daemon.
func spawnDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self) // no subcommand => daemon.Run
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start()
}
