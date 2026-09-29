#!/usr/bin/env bash
# One-command mcvpn server install (Linux x86_64/arm64 VPS).
#   curl -fsSL https://raw.githubusercontent.com/zutkavpn-eng/mc/main/scripts/install.sh | sudo bash
set -euo pipefail

REPO="zutkavpn-eng/mc"
BASE="https://github.com/$REPO/releases/latest/download"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/mcvpn"
CONF="$CONF_DIR/server.toml"
SERVICE="/etc/systemd/system/mcvpn.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo bash)" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) PKG="mcvpn-server-linux-amd64.tar.gz" ;;
  aarch64|arm64) PKG="mcvpn-server-linux-arm64.tar.gz" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo "==> downloading mcvpn-server ($ARCH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl --max-time 60 -fsSL "$BASE/$PKG" -o "$TMP/mcvpn.tar.gz"
tar xzf "$TMP/mcvpn.tar.gz" -C "$TMP"
install -m 755 "$TMP/mcvpn-server" "$BIN_DIR/mcvpn-server"
command -v mcvpn-cli >/dev/null 2>&1 || install -m 755 "$TMP/mcvpn-cli" "$BIN_DIR/mcvpn-cli" 2>/dev/null || true

echo "==> prerequisites"
if ! command -v iptables >/dev/null 2>&1; then
  (apt-get install -y iptables >/dev/null 2>&1 || apt-get update -qq && apt-get install -y iptables >/dev/null 2>&1) || true
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo "    WARNING: iptables not found — the server needs it for NAT (no client internet without it)"
fi
# Persist ip_forward across reboots (the server also sets it at runtime).
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-mcvpn.conf
sysctl -p /etc/sysctl.d/99-mcvpn.conf >/dev/null 2>&1 || true

echo "==> config"
mkdir -p "$CONF_DIR"
if [ -f "$CONF" ]; then
  echo "    keeping existing $CONF"
else
  "$BIN_DIR/mcvpn-server" --init --config "$CONF"
  chmod 600 "$CONF"
fi
TOKEN="$(grep -oP '(?<=^token = ")[^"]+' "$CONF" | head -1)"
PORT="$(grep -oP '(?<=^port = )\d+' "$CONF" | head -1)"
PORT="${PORT:-25565}"

echo "==> systemd service"
UNIT="$SERVICE"
cat > "$SERVICE" <<'EOF'
[Unit]
Description=mcvpn — Minecraft-camouflaged VPN server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mcvpn-server --config /etc/mcvpn/server.toml
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Some VPS kernels ship without the TUN module loaded.
[ -c /dev/net/tun ] || modprobe tun 2>/dev/null || true

if [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable mcvpn
  systemctl restart mcvpn
  # Verify it actually came up (TUN, NAT, port bind all happen at start).
  active=""
  for _ in $(seq 1 20); do
    if systemctl is-active --quiet mcvpn; then active=1; break; fi
    sleep 0.5
  done
  if [ -z "$active" ]; then
    echo "    ERROR: mcvpn.service did not start. Last logs:"
    journalctl -u mcvpn -n 20 --no-pager || true
    echo "    fix the issue above, then: systemctl restart mcvpn"
    exit 1
  fi
  echo "    mcvpn.service active (logs: journalctl -u mcvpn -f)"
  # Server startup diagnostics: TUN data-plane self-test + NAT outcome.
  # --since: only THIS start's lines (an old journal error must not be
  # shown as the verdict of a fresh, healthy start).
  sleep 4
  SELFTEST="$(journalctl -u mcvpn --since "2 minutes ago" --no-pager 2>/dev/null | grep -m1 "TUN self-test" || true)"
  if [ -n "$SELFTEST" ]; then
    echo "    $SELFTEST"
    case "$SELFTEST" in
      *"self-test: OK"*) : ;;
      *) echo "    !!! The server reports its TUN data plane is broken on this host."
         echo "    !!! Clients will connect but will NOT have internet."
         echo "    !!! Check 'ip addr show mcvpn0' — and whether this VPS fully supports"
         echo "    !!! TUN networking (LXC/OpenVZ containers often do not)." ;;
    esac
  fi
  NATLINE="$(journalctl -u mcvpn --since "2 minutes ago" --no-pager 2>/dev/null | grep -m1 "NAT" || true)"
  [ -n "$NATLINE" ] && echo "    $NATLINE"
else
  echo "    systemd not detected (container?) — starting under nohup instead"
  nohup "$BIN_DIR/mcvpn-server" --config "$CONF" >/var/log/mcvpn.log 2>&1 &
  echo "    pid: $! (log: /var/log/mcvpn.log)"
fi

# The port must be listening before we call this a success.
listening=""
for _ in $(seq 1 20); do
  if ss -ltn 2>/dev/null | grep -q ":$PORT " || netstat -ltn 2>/dev/null | grep -q ":$PORT "; then
    listening=1
    break
  fi
  sleep 0.5
done
[ -n "$listening" ] || echo "    WARNING: port $PORT is not listening yet — check the logs above"

echo "==> firewall note"
echo "    make sure TCP 25565 is open on your provider firewall"

IP="$(curl --max-time 5 -fsSL -4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
echo
echo "=============================================================="
echo " mcvpn is running. Connect clients with:"
echo "   server: $IP   port: $PORT"
echo "   token:  $TOKEN"
echo
echo " Or paste this ONE line into the app's Server field (fills everything):"
echo "   mcvpn://$TOKEN@$IP:$PORT"
echo " config: $CONF"
echo " logs:   journalctl -u mcvpn -f"
echo "=============================================================="
