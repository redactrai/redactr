package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

type windowsFirewall struct {
	ruleNames []string
}

func (f *windowsFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			slog.Warn("firewall DNS resolve failed", "domain", domain, "error", err)
			continue
		}
		ipList := strings.Join(ips, ",")
		ruleName := fmt.Sprintf("Redactr-Block-%s", domain)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=out", "action=block",
			"protocol=tcp", "remoteport=443",
			"remoteip="+ipList)
		if err := cmd.Run(); err != nil {
			slog.Warn("firewall netsh error", "domain", domain, "error", err)
		}
		f.ruleNames = append(f.ruleNames, ruleName)
	}
	return nil
}

func (f *windowsFirewall) Unblock() error {
	for _, name := range f.ruleNames {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	}
	f.ruleNames = nil
	return nil
}

func (f *windowsFirewall) Status() ([]Rule, error) {
	var rules []Rule
	for _, name := range f.ruleNames {
		rules = append(rules, Rule{Domain: name, Active: true})
	}
	return rules, nil
}

func (f *windowsFirewall) Cleanup() error {
	return f.Unblock()
}

func (f *windowsFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *windowsFirewall) Unredirect() error                                { return ErrNotImplemented }
func (f *windowsFirewall) IsActive() (bool, error)                          { return false, nil }
