package firewall

import (
	"log/slog"
	"net"
	"os/exec"
)

type linuxFirewall struct {
	blockedIPs []string
}

func (f *linuxFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			slog.Warn("firewall DNS resolve failed", "domain", domain, "error", err)
			continue
		}
		for _, ip := range ips {
			cmd := exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
			if err := cmd.Run(); err != nil {
				slog.Warn("firewall iptables error", "ip", ip, "error", err)
			}
			f.blockedIPs = append(f.blockedIPs, ip)
		}
	}
	return nil
}

func (f *linuxFirewall) Unblock() error {
	for _, ip := range f.blockedIPs {
		exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP").Run()
	}
	f.blockedIPs = nil
	return nil
}

func (f *linuxFirewall) Status() ([]Rule, error) {
	var rules []Rule
	for _, ip := range f.blockedIPs {
		rules = append(rules, Rule{IP: ip, Active: true})
	}
	return rules, nil
}

func (f *linuxFirewall) Cleanup() error {
	return f.Unblock()
}

func (f *linuxFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *linuxFirewall) Unredirect() error                                { return ErrNotImplemented }
func (f *linuxFirewall) IsActive() (bool, error)                          { return false, nil }
