package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/redactrai/redactr/internal/cli"
	"github.com/redactrai/redactr/internal/daemon"
	"github.com/redactrai/redactr/internal/firewall"
	"github.com/redactrai/redactr/internal/tray"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "cleanup":
			runCleanup()
			return
		case "shell":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			if err := cli.RunShell(filepath.Join(home, ".redactr")); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		case "claude", "codex", "copilot":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			if err := cli.RunAgent(filepath.Join(home, ".redactr"), os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		case "tray":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			tray.Run(filepath.Join(home, ".redactr", "state"))
			return
		case "enroll":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			fs := flag.NewFlagSet("enroll", flag.ExitOnError)
			server := fs.String("server", "", "control-plane server URL")
			token := fs.String("token", "", "org enrollment token")
			_ = fs.Parse(os.Args[2:])
			if *server == "" || *token == "" {
				log.Fatalf("usage: redactr enroll --server <url> --token <enrollment-token>")
			}
			if err := cli.RunEnroll(filepath.Join(home, ".redactr"), *server, *token); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		case "code":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			fs := flag.NewFlagSet("code", flag.ExitOnError)
			force := fs.Bool("force", false, "overwrite an existing .devcontainer/devcontainer.json")
			_ = fs.Parse(os.Args[2:])
			project := fs.Arg(0)
			if err := cli.RunCode(filepath.Join(home, ".redactr"), project, *force); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}
	baseDir := filepath.Join(home, ".redactr")
	os.MkdirAll(filepath.Join(baseDir, "certs"), 0o755)
	os.MkdirAll(filepath.Join(baseDir, "data"), 0o755)
	os.MkdirAll(filepath.Join(baseDir, "state"), 0o755)
	if err := daemon.Run(baseDir); err != nil {
		log.Fatalf("daemon: %v", err)
	}
}

func runCleanup() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("home dir: %v", err)
	}
	baseDir := filepath.Join(home, ".redactr")
	statePath := filepath.Join(baseDir, "state", "firewall.json")

	// Set up the macOS Manager so Unredirect works (CA path needed even
	// though we don't install).
	firewall.SetCAPath(filepath.Join(baseDir, "certs", "ca.crt"))
	mgr, err := firewall.New()
	if err == nil && mgr != nil {
		// Flush pf redirect rules (may prompt for sudo on macOS).
		if err := mgr.Unredirect(); err != nil && !errors.Is(err, firewall.ErrNotImplemented) {
			log.Printf("firewall unredirect: %v", err)
		}
		// Also flush legacy block-mode rules.
		if err := mgr.Cleanup(); err != nil && !errors.Is(err, firewall.ErrNotImplemented) {
			log.Printf("firewall cleanup: %v", err)
		}
	}

	// Clear the firewall state file regardless of Unredirect outcome.
	_ = os.Remove(statePath)

	fmt.Println("Firewall rules cleaned up")
}
