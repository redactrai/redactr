package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/devcontainer"
)

type cmdRunner func(name string, args ...string) error

func execRun(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// writeDevcontainer writes content to <project>/.devcontainer/devcontainer.json,
// refusing to overwrite an existing file unless force is set. Returns the path.
func writeDevcontainer(project string, content []byte, force bool) (string, error) {
	dir := filepath.Join(project, ".devcontainer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "devcontainer.json")
	if !force {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	return path, os.WriteFile(path, content, 0o644)
}

// launchDevcontainer invokes the devcontainer CLI to open the workspace.
func launchDevcontainer(project string, run cmdRunner) error {
	return run("devcontainer", "up", "--workspace-folder", project)
}

// RunCode generates a redactr devcontainer for the project and opens it. It
// preflights the daemon + proxy + launch policy exactly like RunAgent.
func RunCode(baseDir, project string, force bool) error {
	if project == "" {
		project = "."
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	sockDir := filepath.Join(baseDir, "state")
	if err := EnsureDaemon(sockDir); err != nil {
		return err
	}
	client := NewClient(sockDir)
	if _, err := client.EnableProxy(); err != nil {
		return fmt.Errorf("could not enable proxy: %w", err)
	}
	info, err := client.LaunchPolicy("code")
	if err != nil {
		return fmt.Errorf("could not fetch launch policy: %w", err)
	}
	content, err := devcontainer.Generate(devcontainer.GenerateInput{
		Image: info.Image, ProxyAddr: info.ProxyAddr, CACertPath: filepath.Join(baseDir, "certs", "ca.crt"),
	})
	if err != nil {
		return err
	}
	path, err := writeDevcontainer(abs, content, force)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("devcontainer"); err != nil {
		fmt.Fprintf(os.Stderr, "wrote %s\nOpen this folder in VS Code and choose \"Reopen in Container\".\n", path)
		return nil
	}
	fmt.Fprintf(os.Stderr, "wrote %s — starting dev container…\n", path)
	return launchDevcontainer(abs, execRun)
}
