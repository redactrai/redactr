package sandbox

import (
	"fmt"
	"os/exec"
)

// Runtime is a container runtime driver.
type Runtime interface {
	Name() string
	// RunArgs returns the full argv (including the binary) to run spec, given
	// the already-composed flag groups.
	RunArgs(flags []string, image string, entrypoint []string) []string
}

type cliRuntime struct{ bin string }

func (r cliRuntime) Name() string { return r.bin }

func (r cliRuntime) RunArgs(flags []string, image string, entrypoint []string) []string {
	argv := []string{r.bin, "run"}
	argv = append(argv, flags...)
	argv = append(argv, image)
	argv = append(argv, entrypoint...)
	return argv
}

// preferredRuntimes is the detection order; docker first (also covers Colima).
var preferredRuntimes = []string{"docker", "podman"}

// Detect returns the first available container runtime on PATH.
func Detect() (Runtime, error) {
	for _, bin := range preferredRuntimes {
		if _, err := exec.LookPath(bin); err == nil {
			return cliRuntime{bin: bin}, nil
		}
	}
	return nil, fmt.Errorf("no container runtime found (install Docker, Colima, or Podman)")
}
