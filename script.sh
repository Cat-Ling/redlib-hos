#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# script.sh — do the heavy lifting here to avoid YAML issues.
# Place this at the repo root and make executable (workflow will chmod +x).

if [ -z "${TAILSCALE_AUTH_KEY:-}" ]; then
  echo "ERROR: TAILSCALE_AUTH_KEY environment variable not set. Provide it as a repo/org secret." >&2
  exit 2
fi

echo "=== Starting script.sh ==="
sudo apt-get update -y

# Install required packages (best-effort)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  curl iproute2 iptables iptables-persistent openssh-server ca-certificates gnupg lsb-release || true

# Install Tailscale (official install script)
curl -fsSL https://tailscale.com/install.sh | sh

# Ensure tailscaled is enabled & started
sudo systemctl enable --now tailscaled || true

# Ensure SSHD available
sudo mkdir -p /var/run/sshd
sudo systemctl enable --now ssh || true

# Enable IPv4 and IPv6 forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Persist forwarding (best-effort)
sudo sh -c 'printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n" > /etc/sysctl.d/99-github-tailscale.conf'
sudo sysctl --system || true

# Detect egress interfaces (best-effort)
EG_IF_IPV4=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)
EG_IF_IPV6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)

EG_IF_IPV4=${EG_IF_IPV4:-eth0}
EG_IF_IPV6=${EG_IF_IPV6:-$EG_IF_IPV4}

echo "Using IPv4 egress interface: $EG_IF_IPV4"
echo "Using IPv6 egress interface: $EG_IF_IPV6"

# Configure IPv4 NAT (masquerade) so exit-node clients can reach the internet
# Add rules only if they don't already exist
sudo iptables -t nat -C POSTROUTING -o "$EG_IF_IPV4" -j MASQUERADE 2>/dev/null || \
  sudo iptables -t nat -A POSTROUTING -o "$EG_IF_IPV4" -j MASQUERADE

# Allow forwarding between tailscale0 and egress iface
sudo iptables -C FORWARD -i tailscale0 -o "$EG_IF_IPV4" -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -i tailscale0 -o "$EG_IF_IPV4" -j ACCEPT

sudo iptables -C FORWARD -i "$EG_IF_IPV4" -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -i "$EG_IF_IPV4" -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# IPv6 forwarding allowances (no NAT)
sudo ip6tables -C FORWARD -i tailscale0 -o "$EG_IF_IPV6" -j ACCEPT 2>/dev/null || \
  sudo ip6tables -A FORWARD -i tailscale0 -o "$EG_IF_IPV6" -j ACCEPT

sudo ip6tables -C FORWARD -i "$EG_IF_IPV6" -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  sudo ip6tables -A FORWARD -i "$EG_IF_IPV6" -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Persist iptables (best-effort)
sudo mkdir -p /etc/iptables
sudo sh -c "iptables-save > /etc/iptables/rules.v4" || true
sudo sh -c "ip6tables-save > /etc/iptables/rules.v6" || true

# Bring up Tailscale with SSH and advertise as exit node + default routes.
# NOTE: Advertising 0.0.0.0/0 and ::/0 may require admin approval in Tailscale admin console.
sudo tailscale up \
  --authkey="${TAILSCALE_AUTH_KEY}" \
  --ssh \
  --advertise-exit-node \
  --advertise-routes=0.0.0.0/0,::/0 || {
    echo "tailscale up failed — check logs and admin approval. Continuing to status output..."
  }

# Show status & IPs
echo "=== Tailscale status ==="
sudo tailscale status || true
echo "Tailscale IPs (v4):"
sudo tailscale ip -4 || true
echo "Tailscale IPs (v6):"
sudo tailscale ip -6 || true

# --- Random output loop to keep the job alive and print once per minute ---
echo "Starting random output loop. Cancel the workflow to stop."

PHRASES=(
  "🍀 all systems go"
  "🔁 heartbeat"
  "✨ ephemeral runner alive"
  "🛰 tailscale tunnel active"
  "🔐 ssh ready"
  "🌐 advertising exit node"
  "🕒 minute tick"
  "🌟 random thought"
)

# infinite loop; prints one phrase per minute
while true; do
  i=$((RANDOM % ${#PHRASES[@]}))
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - ${PHRASES[$i]}"
  sleep 60
done
