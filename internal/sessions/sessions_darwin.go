//go:build darwin

package sessions

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type rawProc struct {
	PID       int
	PPID      int
	User      string
	Command   string
	StartedAt time.Time
}

func scanProcesses() ([]rawProc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ps", "-axwwo", "pid=,ppid=,user=,lstart=,command=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}

	var procs []rawProc
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// pid ppid user "Wed Apr 23 09:08:24 2026" command…
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		user := fields[2]
		// lstart is exactly 5 fields: "Wed Apr 23 09:08:24 2026"
		lstartStr := strings.Join(fields[3:8], " ")
		startedAt, _ := time.ParseInLocation(time.ANSIC, lstartStr, time.Local)
		command := strings.Join(fields[8:], " ")
		procs = append(procs, rawProc{
			PID:       pid,
			PPID:      ppid,
			User:      user,
			Command:   command,
			StartedAt: startedAt,
		})
	}
	return procs, scanner.Err()
}

func processEnv(pid int) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ps", "-Ewwwo", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, fmt.Errorf("ps -E: %w", err)
	}
	// Output is one line: command + space-separated KEY=VALUE pairs after the
	// argv. We need to identify env entries — env entries always look like
	// IDENT=value where IDENT is uppercase or lowercase identifier. We use a
	// permissive split: tokenize by whitespace, take only tokens with '='.
	env := make(map[string]string)
	for _, tok := range strings.Fields(strings.TrimSpace(string(out))) {
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			key := tok[:eq]
			if isEnvKey(key) {
				env[key] = tok[eq+1:]
			}
		}
	}
	return env, nil
}

func isEnvKey(k string) bool {
	if k == "" {
		return false
	}
	// Letters, digits, underscore. First char a letter or underscore.
	c := k[0]
	if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func processConnections(pid int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-a", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		// lsof returns non-zero when a pid has no matching file descriptors,
		// so distinguish that from a real failure.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && len(out) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("lsof: %w", err)
	}

	var conns []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "->") {
			continue
		}
		// Example NAME column: 192.168.1.5:53842->17.253.21.10:443 (ESTABLISHED)
		idx := strings.Index(line, "->")
		if idx < 0 {
			continue
		}
		rest := line[idx+2:]
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		conns = append(conns, strings.TrimSpace(rest[:end]))
	}
	return conns, scanner.Err()
}

func lookupHost(h string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var r net.Resolver
	addrs, err := r.LookupHost(ctx, h)
	return addrs, err
}

// Stop sends SIGTERM to the given PID. Returns an error if the process does
// not exist or the signal cannot be delivered.
func Stop(pid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kill", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill %d: %w (%s)", pid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchProtectedShell opens a new Terminal.app window running `redactr shell`
// using the given binary path. Returns an error if osascript is unavailable
// or the launch fails.
func LaunchProtectedShell(redactrBinary string) error {
	if redactrBinary == "" {
		return fmt.Errorf("redactr binary path not provided")
	}
	script := fmt.Sprintf(`tell application "Terminal"
		activate
		do script %q
	end tell`, redactrBinary+" shell")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("osascript: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PlatformSupported reports whether session discovery is available on this OS.
func PlatformSupported() bool { return true }
