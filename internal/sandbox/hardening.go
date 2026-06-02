package sandbox

// HardeningArgs returns the non-negotiable hardening flags for `run`.
// runtime is the driver name ("docker" or "podman") for driver-specific tweaks.
func HardeningArgs(runtime string) []string {
	args := []string{
		"--cap-drop", "ALL",
		// Measured exception: the entrypoint installs the egress redirect over
		// the container's own netns before dropping to an unprivileged user.
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp",
		// Writable scratch for the unprivileged agent's HOME (read-only root
		// otherwise leaves CLIs like claude nowhere to write their config).
		"--tmpfs", "/home/redactr:uid=1000,mode=0700",
		"--pids-limit", "512",
		"--memory", "4g",
	}
	if runtime == "podman" {
		// Map the invoking host user into the container (rootless).
		args = append(args, "--userns", "keep-id")
	}
	return args
}
