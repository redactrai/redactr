#!/bin/sh
set -e

PROXY_HOST="${REDACTR_PROXY_HOST:-host.docker.internal}"
PROXY_PORT="${REDACTR_PROXY_PORT:-47474}"

# Resolve the host-gateway alias to an IP for NAT rules.
PROXY_IP="$(getent hosts "$PROXY_HOST" | awk '{print $1; exit}')"

if [ -n "$PROXY_IP" ]; then
	# Redirect all outbound TCP 80/443 to the local proxy on the host gateway.
	iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination "$PROXY_IP:$PROXY_PORT"
	iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP:$PROXY_PORT"

	# Default-deny egress. Only the rules below may leave the container; every
	# other protocol/port (UDP, ICMP, odd TCP ports) is dropped by the policy.
	# This is the exfil boundary.
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# DNS only to the container's own configured resolvers (blocks DNS-tunnel
	# exfil to an attacker-controlled resolver). Loopback resolvers (e.g. Docker's
	# embedded 127.0.0.11) are already covered by the -o lo rule above.
	for ns in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null); do
		iptables -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT
		iptables -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT
	done

	# The local proxy: post-DNAT destination for all 80/443 traffic.
	iptables -A OUTPUT -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT
	# SEAM: admin port-allowlist (e.g. 22 for SSH git) inserted here from policy.

	# Drop everything not explicitly allowed above, across all protocols.
	iptables -P OUTPUT DROP
else
	echo "redactr: WARNING could not resolve $PROXY_HOST; egress redirect not installed" >&2
fi

# Drop NET_ADMIN-holding root; run the agent unprivileged.
exec gosu redactr "$@"
