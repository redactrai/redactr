package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rakeshguha/redactr/internal/mcpwrap"
	"github.com/rakeshguha/redactr/internal/sandbox"
)

type apiScanner struct {
	baseURL string
	client  *http.Client
}

func (s *apiScanner) ScanText(text string) (string, error) {
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := s.client.Post(s.baseURL+"/api/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		return text, err
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if redacted, ok := result["redacted"]; ok {
		return redacted, nil
	}
	return text, nil
}

// resolveChild decides the child process argv. Default: run the given command
// as a host child (unchanged, backward compatible). With a leading "--container"
// (optionally "--image <ref>"), the command runs inside a redactr container via
// the provided containerArgv builder.
func resolveChild(args []string, containerArgv func(image string, entrypoint []string) ([]string, error)) ([]string, error) {
	if len(args) == 0 || args[0] != "--container" {
		return args, nil
	}
	args = args[1:]
	image := "redactr-base:local" // SEAM: use the daemon's launch-policy image when enrolled
	if len(args) >= 1 && args[0] == "--image" {
		if len(args) < 2 {
			return nil, fmt.Errorf("redactr-mcp-wrap --container --image: missing image reference")
		}
		image, args = args[1], args[2:]
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("redactr-mcp-wrap --container: missing MCP server command")
	}
	return containerArgv(image, args)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: redactr-mcp-wrap [--container [--image <ref>]] <command> [args...]\n")
		os.Exit(1)
	}

	var scanner mcpwrap.RemoteScanner
	apiPort := discoverAPIPort()
	if apiPort != "" {
		scanner = &apiScanner{
			baseURL: "http://127.0.0.1:" + apiPort,
			client:  &http.Client{Timeout: 5 * time.Second},
		}
	}

	childArgv, err := resolveChild(os.Args[1:], func(image string, entry []string) ([]string, error) {
		home, _ := os.UserHomeDir()
		base := filepath.Join(home, ".redactr")
		proxyAddr, caPath, derr := sandbox.Discover(base)
		if derr != nil {
			return nil, derr
		}
		cwd, _ := os.Getwd()
		eng, eerr := sandbox.NewEngine()
		if eerr != nil {
			return nil, eerr
		}
		return eng.StdioRunArgs(sandbox.Spec{
			Mode: sandbox.ModeStdioAttached, Image: image, ProjectDir: cwd,
			Entrypoint: entry, ProxyAddr: proxyAddr, CACertPath: caPath,
		})
	})
	if err != nil {
		log.Fatalf("redactr-mcp-wrap: %v", err)
	}
	cmd := exec.Command(childArgv[0], childArgv[1:]...)
	cmd.Stderr = os.Stderr

	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start MCP server: %v", err)
	}

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := sc.Bytes()
			scanned, _ := mcpwrap.ScanMessage(line, scanner)
			stdin.Write(scanned)
			stdin.Write([]byte("\n"))
		}
		stdin.Close()
	}()

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Bytes()
		scanned, _ := mcpwrap.ScanMessage(line, scanner)
		os.Stdout.Write(scanned)
		os.Stdout.Write([]byte("\n"))
	}

	cmd.Wait()
}

func discoverAPIPort() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".redactr", "state", "api.port"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
