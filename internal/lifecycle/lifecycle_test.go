//go:build unix

package lifecycle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAcquireSingleton_NoPredecessor(t *testing.T) {
	dir := t.TempDir()

	lock, err := AcquireSingleton(dir, nil, Options{})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer lock.Release()

	pidPath := filepath.Join(dir, pidfileName)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("pidfile has %d, want %d", pid, os.Getpid())
	}
}

func TestAcquireSingleton_StalePidfile(t *testing.T) {
	dir := t.TempDir()
	// Spawn a child, capture its PID, kill it, then write that PID to the
	// pidfile. The pidfile is now stale (PID points to a dead process).
	cmd := exec.Command("sleep", "0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	deadPid := cmd.Process.Pid
	_ = cmd.Wait()

	pidPath := filepath.Join(dir, pidfileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", deadPid)), 0o644); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}

	lock, err := AcquireSingleton(dir, nil, Options{})
	if err != nil {
		t.Fatalf("acquire over stale pidfile: %v", err)
	}
	defer lock.Release()

	data, _ := os.ReadFile(pidPath)
	if !strings.HasPrefix(strings.TrimSpace(string(data)), strconv.Itoa(os.Getpid())) {
		t.Fatalf("pidfile not reclaimed; got %q", data)
	}
}

func TestAcquireSingleton_LivePredecessor_RespondsToSIGTERM(t *testing.T) {
	dir := t.TempDir()
	predecessor := startPredecessor(t, dir, false)
	defer predecessor.Wait()

	start := time.Now()
	lock, err := AcquireSingleton(dir, nil, Options{
		IsOurProcess: alwaysOurs,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("acquire over live predecessor: %v", err)
	}
	defer lock.Release()

	if elapsed > 4*time.Second {
		t.Errorf("SIGTERM-responsive predecessor took %v; expected sub-second", elapsed)
	}
	if processAlive(predecessor.pid) {
		t.Errorf("predecessor pid %d still alive after acquire", predecessor.pid)
	}
}

func TestAcquireSingleton_LivePredecessor_IgnoresSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("requires SIGTERM grace timeout")
	}
	dir := t.TempDir()
	predecessor := startPredecessor(t, dir, true)
	defer predecessor.Wait()

	start := time.Now()
	lock, err := AcquireSingleton(dir, nil, Options{
		GraceTimeout: 500 * time.Millisecond,
		IsOurProcess: alwaysOurs,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("acquire over SIGTERM-ignoring predecessor: %v", err)
	}
	defer lock.Release()

	if elapsed < 400*time.Millisecond {
		t.Errorf("acquire returned in %v; should have waited for grace timeout", elapsed)
	}
	if processAlive(predecessor.pid) {
		t.Errorf("predecessor pid %d still alive after SIGKILL path", predecessor.pid)
	}
}

func TestAcquireSingleton_PIDReuseRefuses(t *testing.T) {
	dir := t.TempDir()
	predecessor := startPredecessor(t, dir, false)
	defer func() {
		_ = syscall.Kill(predecessor.pid, syscall.SIGKILL)
		predecessor.Wait()
	}()

	_, err := AcquireSingleton(dir, nil, Options{
		IsOurProcess: func(pid int) bool { return false },
	})
	if err == nil {
		t.Fatalf("expected refusal when IsOurProcess returns false")
	}
	if !strings.Contains(err.Error(), "not a redactr process") {
		t.Errorf("error %q should mention non-redactr process", err)
	}
	if !processAlive(predecessor.pid) {
		t.Errorf("predecessor pid %d was killed despite IsOurProcess=false", predecessor.pid)
	}
}

func TestRelease_AllowsReacquire(t *testing.T) {
	dir := t.TempDir()

	lock1, err := AcquireSingleton(dir, nil, Options{})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := lock1.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	lock2, err := AcquireSingleton(dir, nil, Options{})
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	defer lock2.Release()
}

func TestReapOrphans_NoState(t *testing.T) {
	dir := t.TempDir()
	if err := ReapOrphans(dir, nil, nil); err != nil {
		t.Fatalf("reap with no state should succeed: %v", err)
	}
}

func TestReapOrphans_KillsListenerOnSidecarPort(t *testing.T) {
	dir := t.TempDir()
	// Spawn a child that holds a TCP listener so lsof can find it.
	port, child := startTCPHolder(t)
	defer func() {
		_ = syscall.Kill(child.Process.Pid, syscall.SIGKILL)
		child.Wait()
	}()

	if err := os.WriteFile(
		filepath.Join(dir, "sidecar.port"),
		[]byte(strconv.Itoa(port)),
		0o644,
	); err != nil {
		t.Fatalf("write sidecar.port: %v", err)
	}

	if err := ReapOrphans(dir, nil, nil); err != nil {
		t.Fatalf("reap: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(child.Process.Pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if processAlive(child.Process.Pid) {
		t.Errorf("child pid %d still alive after reap", child.Process.Pid)
	}

	if _, err := os.Stat(filepath.Join(dir, "sidecar.port")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sidecar.port not removed after reap")
	}
}

func TestReapOrphans_FirewallErrors(t *testing.T) {
	dir := t.TempDir()
	fw := &fakeCleaner{
		unredirectErr: errors.New("boom"),
	}
	err := ReapOrphans(dir, fw, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected boom error, got %v", err)
	}
	if !fw.unredirectCalled || !fw.cleanupCalled {
		t.Errorf("expected both Unredirect and Cleanup to be called; got %+v", fw)
	}
}

// helpers

type predecessor struct {
	cmd  *exec.Cmd
	pid  int
	done chan struct{}
}

func (p *predecessor) Wait() {
	if p.done != nil {
		<-p.done
	}
}

// startPredecessor spawns a process that holds an exclusive flock on the
// pidfile in dir, simulating a live redactr instance. If ignoreSigterm is
// true, the process traps SIGTERM and continues running.
func startPredecessor(t *testing.T, dir string, ignoreSigterm bool) *predecessor {
	t.Helper()
	pidPath := filepath.Join(dir, pidfileName)

	// Use flock(1) if available, otherwise a Python one-liner. macOS doesn't
	// ship flock(1), so use a portable Python script.
	trap := ""
	if ignoreSigterm {
		trap = "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
	}
	script := fmt.Sprintf(
		"import fcntl, os, sys, time; %s"+
			"f=open(%q,'w'); fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB); "+
			"f.write(str(os.getpid())); f.flush(); "+
			"sys.stdout.write('ready\\n'); sys.stdout.flush(); "+
			"time.sleep(60)",
		trap, pidPath,
	)
	cmd := exec.Command("python3", "-c", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start predecessor: %v", err)
	}

	// Wait for "ready" so we know the flock is held and pid is written.
	buf := make([]byte, 16)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := stdout.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), "ready") {
			break
		}
	}

	p := &predecessor{cmd: cmd, pid: cmd.Process.Pid, done: make(chan struct{})}
	// Reap the child in the background so processAlive sees ESRCH promptly
	// after SIGKILL — otherwise the killed child sits as a zombie until the
	// parent (this test process) waits on it.
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	return p
}

func startTCPHolder(t *testing.T) (int, *exec.Cmd) {
	t.Helper()
	// Pick a free port first.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	script := fmt.Sprintf(
		"import socket, time; "+
			"s=socket.socket(); s.bind(('127.0.0.1', %d)); s.listen(1); "+
			"time.sleep(60)",
		port,
	)
	cmd := exec.Command("python3", "-c", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcp holder: %v", err)
	}
	// Reap in background so processAlive sees the child die promptly.
	go func() { _ = cmd.Wait() }()

	// Wait until the port is actually listening.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return port, cmd
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tcp holder never listened on %d", port)
	return port, cmd
}

func alwaysOurs(int) bool { return true }

type fakeCleaner struct {
	unredirectCalled bool
	cleanupCalled    bool
	unredirectErr    error
	cleanupErr       error
}

func (f *fakeCleaner) Unredirect() error {
	f.unredirectCalled = true
	return f.unredirectErr
}

func (f *fakeCleaner) Cleanup() error {
	f.cleanupCalled = true
	return f.cleanupErr
}
