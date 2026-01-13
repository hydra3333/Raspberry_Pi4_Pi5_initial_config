#!/usr/bin/env bash
#
# install-nft-vpn-lan-isolation.sh
#
# Raspberry Pi OS (Trixie) — Pi 4 / Pi 5
# nftables + NetworkManager dispatcher
#
# BASELINE (secure LAN host posture):
#   - INPUT  policy DROP   (equivalent of: ufw default deny incoming)
#   - OUTPUT policy ACCEPT (equivalent of: ufw default allow outgoing)
#   - Allow loopback + established/related
#   - Allow only explicitly enabled LAN-only inbound services
#
# VPN OVERLAY (on-the-fly):
#   - When VPN is UP (interface name matches nordlynx|tunN|wgN):
#       * DROP inbound from LAN hosts (10.0.0.0/24) except gateway (10.0.0.1)
#       * DROP outbound to   LAN hosts (10.0.0.0/24) except gateway (10.0.0.1)
#     This provides full LAN isolation while still allowing routing/VPN via the gateway.
#
# Files created:
#   - /etc/nftables.conf
#   - /usr/local/sbin/vpn-lan-isolation.sh
#   - /etc/NetworkManager/dispatcher.d/90-vpn-lan-isolation
#
# Usage:
#   sudo bash ./install-nft-vpn-lan-isolation.sh
#

set -euo pipefail

# ----------------------------
# USER SETTINGS
# ----------------------------

LAN_CIDR="10.0.0.0/24"
GATEWAY_IP="10.0.0.1"

# VPN interface detection (NordLynx, OpenVPN, WireGuard)
VPN_IFACE_REGEX='^(nordlynx|tun[0-9]+|wg[0-9]+)$'

# ----------------------------
# Enabled LAN-only inbound services (VPN DOWN only)
# ----------------------------

# SSH server (also provides SFTP for FileZilla)
ALLOW_SSH=true
SSH_PORT="22"

# VNC server (display :0 usually 5900)
ALLOW_VNC=true
VNC_PORTS="5900"          # e.g. "5900" or "5900-5910" or "5900,5901,5902"

# Samba/SMB server
ALLOW_SAMBA=true
# Samba ports:
#   UDP 137 (netbios-ns), UDP 138 (netbios-dgm), TCP 139 (netbios-ssn), TCP 445 (microsoft-ds)

# Optional: MiniDLNA
ALLOW_MINIDLNA=false
MINIDLNA_HTTP_PORT="8200"     # MiniDLNA HTTP/control port
ALLOW_SSDP_DISCOVERY=false    # UDP 1900 (often required for DLNA discovery)

# Optional diagnostics
ALLOW_ICMP=true               # ping + PMTU discovery

# ----------------------------
# INTERNALS
# ----------------------------

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: Run as root (use sudo)." >&2
    exit 1
  fi
}

install_packages() {
  apt-get update -y
  apt-get install -y nftables
}

enable_services() {
  systemctl enable --now nftables
  systemctl enable --now NetworkManager >/dev/null 2>&1 || true
}

write_nftables_conf() {
  local f="/etc/nftables.conf"

  cat > "${f}" <<EOF
#!/usr/sbin/nft -f
#
# nftables base firewall — Raspberry Pi OS (Trixie)
#
# Baseline posture:
#   - INPUT  policy DROP   (deny inbound by default)
#   - OUTPUT policy ACCEPT (allow outbound by default)
#   - Allow loopback and established/related traffic
#   - Allow selected inbound services from LAN only
#
# VPN overlay:
#   - Applied dynamically by /usr/local/sbin/vpn-lan-isolation.sh (called via NetworkManager dispatcher)
#

flush ruleset

table inet filter {

  chain input {
    type filter hook input priority 0; policy drop;

    # Always allow loopback
    iifname "lo" accept

    # Allow return traffic for established outbound connections
    ct state established,related accept

EOF

  if [[ "${ALLOW_ICMP}" == "true" ]]; then
    cat >> "${f}" <<'EOF'
    # ICMP is useful for diagnostics and PMTU discovery
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

EOF
  fi

  cat >> "${f}" <<EOF
    # ------------------------------------------------------------
    # LAN-only inbound services (effective when VPN isolation is OFF)
    # Source constrained to: ${LAN_CIDR}
    # ------------------------------------------------------------

EOF

  if [[ "${ALLOW_SSH}" == "true" ]]; then
    cat >> "${f}" <<EOF
    # SSH server (also provides SFTP for FileZilla)
    ip saddr ${LAN_CIDR} tcp dport ${SSH_PORT} accept

EOF
  fi

  if [[ "${ALLOW_VNC}" == "true" ]]; then
    cat >> "${f}" <<EOF
    # VNC server (commonly TCP 5900 for display :0)
    ip saddr ${LAN_CIDR} tcp dport {${VNC_PORTS}} accept

EOF
  fi

  if [[ "${ALLOW_SAMBA}" == "true" ]]; then
    cat >> "${f}" <<EOF
    # Samba/SMB server (Windows file sharing)
    # UDP 137/138: NetBIOS name service/datagrams (legacy/discovery)
    # TCP 139/445: SMB session ports (445 is primary modern SMB)
    ip saddr ${LAN_CIDR} udp dport {137,138} accept
    ip saddr ${LAN_CIDR} tcp dport {139,445} accept

EOF
  fi

  if [[ "${ALLOW_MINIDLNA}" == "true" ]]; then
    cat >> "${f}" <<EOF
    # MiniDLNA server (HTTP/control/content)
    ip saddr ${LAN_CIDR} tcp dport ${MINIDLNA_HTTP_PORT} accept

EOF
    if [[ "${ALLOW_SSDP_DISCOVERY}" == "true" ]]; then
      cat >> "${f}" <<EOF
    # SSDP discovery for DLNA (often required for clients to discover MiniDLNA)
    # Typically multicast to 239.255.255.250:1900; allowing LAN-sourced UDP 1900 helps discovery.
    ip saddr ${LAN_CIDR} udp dport 1900 accept

EOF
    fi
  else
    cat >> "${f}" <<'EOF'
    # MiniDLNA optional additions (disabled by default):
    #   - TCP 8200 for MiniDLNA HTTP/control/content
    #   - UDP 1900 for SSDP discovery (if clients fail to discover)
    #
    # Example (enable if desired):
    #   ip saddr 10.0.0.0/24 tcp dport 8200 accept
    #   ip saddr 10.0.0.0/24 udp dport 1900 accept

EOF
  fi

  cat >> "${f}" <<'EOF'
    # End of explicit inbound service rules
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;

    # Output is allowed by default.
    # When VPN is UP, we dynamically DROP traffic to LAN hosts except the gateway.
  }
}
EOF

  chmod 0644 "${f}"
}

write_toggle_script() {
  local f="/usr/local/sbin/vpn-lan-isolation.sh"

  cat > "${f}" <<EOF
#!/usr/bin/env bash
#
# vpn-lan-isolation.sh
#
# Applies/removes the VPN overlay:
#   - VPN UP  -> DROP LAN host traffic (10.0.0.0/24) except gateway 10.0.0.1
#   - VPN DOWN-> Remove those DROP rules
#
# This yields "VPN connected => Pi cannot see LAN" without breaking routing/VPN.
#

set -euo pipefail

LAN_CIDR="${LAN_CIDR}"
GATEWAY_IP="${GATEWAY_IP}"
VPN_IFACE_REGEX='${VPN_IFACE_REGEX}'
TAG="vpn_lan_isolation__drop_lan_except_gateway"

vpn_is_up() {
  ip -o link show up \
    | awk -F': ' '{print $2}' \
    | grep -Eq "${VPN_IFACE_REGEX}"
}

remove_rules() {
  while read -r handle; do
    nft delete rule inet filter input handle "$handle"
  done < <(nft -a list chain inet filter input | awk -v tag="$TAG" '$0 ~ tag {print $NF}')

  while read -r handle; do
    nft delete rule inet filter output handle "$handle"
  done < <(nft -a list chain inet filter output | awk -v tag="$TAG" '$0 ~ tag {print $NF}')
}

add_rules() {
  # Insert near top so these DROPs override service allows.
  # INPUT: block LAN hosts reaching the Pi (except gateway)
  nft insert rule inet filter input position 3 ip saddr \$LAN_CIDR ip saddr != \$GATEWAY_IP drop comment "\$TAG" 2>/dev/null || true
  # OUTPUT: block Pi reaching LAN hosts (except gateway)
  nft insert rule inet filter output position 1 ip daddr \$LAN_CIDR ip daddr != \$GATEWAY_IP drop comment "\$TAG" 2>/dev/null || true
}

case "\${1:-}" in
  apply)
    if vpn_is_up; then
      add_rules
      echo "VPN is UP: LAN isolation ENABLED (except gateway \$GATEWAY_IP)."
    else
      remove_rules
      echo "VPN is DOWN: LAN isolation DISABLED."
    fi
    ;;
  on)
    add_rules
    echo "LAN isolation ENABLED."
    ;;
  off)
    remove_rules
    echo "LAN isolation DISABLED."
    ;;
  status)
    echo "VPN interface UP?"; vpn_is_up && echo "yes" || echo "no"
    echo
    echo "Isolation rules present?"
    nft -a list chain inet filter input  | grep -F "\$TAG" || true
    nft -a list chain inet filter output | grep -F "\$TAG" || true
    ;;
  *)
    echo "Usage: \$0 {apply|on|off|status}"
    exit 2
    ;;
esac
EOF

  chmod 0755 "${f}"
}

write_nm_dispatcher() {
  local f="/etc/NetworkManager/dispatcher.d/90-vpn-lan-isolation"

  cat > "${f}" <<'EOF'
#!/usr/bin/env bash
#
# NetworkManager dispatcher hook:
# Re-evaluates VPN state and applies/removes LAN isolation on relevant network events.
#
# NM calls: script <interface> <action>
#

set -euo pipefail

ACTION="${2:-}"

case "$ACTION" in
  up|down|pre-up|vpn-up|vpn-down|dhcp4-change|dhcp6-change|connectivity-change)
    ;;
  *)
    exit 0
    ;;
esac

/usr/local/sbin/vpn-lan-isolation.sh apply >/dev/null 2>&1 &

exit 0
EOF

  chmod 0755 "${f}"
}

load_firewall_now() {
  nft -f /etc/nftables.conf
}

apply_initial_state() {
  /usr/local/sbin/vpn-lan-isolation.sh apply
}

print_summary() {
  echo
  echo "============================================================"
  echo "Installed nftables + NetworkManager dispatcher for VPN/LAN isolation."
  echo
  echo "Baseline posture:"
  echo "  - INPUT  policy DROP (deny inbound by default)"
  echo "  - OUTPUT policy ACCEPT (allow outbound by default)"
  echo "  - Explicit LAN-only inbound services are enabled when VPN is DOWN"
  echo "  - When VPN is UP, LAN host traffic is dropped (except gateway ${GATEWAY_IP})"
  echo
  echo "Installed files:"
  echo "  - /etc/nftables.conf"
  echo "  - /usr/local/sbin/vpn-lan-isolation.sh"
  echo "  - /etc/NetworkManager/dispatcher.d/90-vpn-lan-isolation"
  echo
  echo "Useful commands:"
  echo "  sudo /usr/local/sbin/vpn-lan-isolation.sh status"
  echo "  sudo nft list ruleset"
  echo
  echo "Suggested tests:"
  echo "  VPN DOWN: from LAN PC -> SSH/SFTP, VNC, SMB to the Pi should work."
  echo "  VPN UP  : ping 10.0.0.2 should FAIL; ping ${GATEWAY_IP} should still work."
  echo "============================================================"
}

main() {
  require_root
  install_packages
  enable_services
  write_nftables_conf
  write_toggle_script
  write_nm_dispatcher
  load_firewall_now
  apply_initial_state
  print_summary
}

main "$@"
