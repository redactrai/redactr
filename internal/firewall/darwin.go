package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

type darwinFirewall struct {
	active bool
}

func (f *darwinFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			slog.Warn("firewall DNS resolve failed", "domain", domain, "error", err)
			continue
		}
		for _, ip := range ips {
			rule := fmt.Sprintf("block drop out proto tcp from any to %s port 443", ip)
			cmd := exec.Command("pfctl", "-a", "com.redactr", "-f", "-")
			cmd.Stdin = strings.NewReader(rule + "\n")
			if err := cmd.Run(); err != nil {
				slog.Warn("firewall pfctl error", "ip", ip, "error", err)
			}
		}
	}
	f.active = true
	return nil
}

func (f *darwinFirewall) Unblock() error {
	cmd := exec.Command("pfctl", "-a", "com.redactr", "-F", "all")
	f.active = false
	return cmd.Run()
}

func (f *darwinFirewall) Status() ([]Rule, error) {
	if !f.active {
		return nil, nil
	}
	cmd := exec.Command("pfctl", "-a", "com.redactr", "-sr")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			rules = append(rules, Rule{Domain: "parsed-from-rule", Active: true})
		}
	}
	return rules, nil
}

func (f *darwinFirewall) Cleanup() error {
	return f.Unblock()
}
