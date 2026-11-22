#!/bin/sh
# sink_setup.sh - configure the lab-sink VM (Debian 13). Run as root, once,
# with sink.py in the same directory. Afterwards the VM must be attached ONLY
# to the internal network "labnet".
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)

# --- static address on the internal network -----------------------------------
IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $IFACE
iface $IFACE inet static
    address 10.0.0.2/24
EOF

# --- sink service ---------------------------------------------------------------
install -d /opt/sink /var/log/sink
install -m 0755 "$HERE/sink.py" /opt/sink/sink.py
cat > /etc/systemd/system/sink.service <<'EOF'
[Unit]
Description=Lab network sink (DNS + catch-all TCP)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/sink/sink.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- redirect every inbound TCP port (except ssh) to the catch-all listener -----
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        iifname "$IFACE" udp dport 53 redirect to :53
        iifname "$IFACE" tcp dport != { 22, 8000 } redirect to :8000
    }
}
EOF

# no resolver of its own: nothing here should look anything up
systemctl disable --now systemd-resolved 2>/dev/null || true
systemctl enable nftables sink
echo "sink setup done (iface=$IFACE); reboot to apply the static address"
