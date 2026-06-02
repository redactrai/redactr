//go:build !darwin && !windows

package tray

import (
	"fmt"
	"os"
)

// Run is a stub on platforms without a native system tray (the tray is
// supported on macOS and Windows).
func Run(sockDir string) {
	fmt.Fprintln(os.Stderr, "redactr tray is only supported on macOS and Windows")
}
