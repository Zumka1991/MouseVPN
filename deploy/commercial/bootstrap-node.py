#!/usr/bin/env python3
"""Prepare an additional subscription node; never replace an existing node or firewall.

Run as root from a staging directory containing relay-agent. Register the printed
public metadata with the controller (initially disabled), install node.token with
owner relaynode and mode 0600, then enable relay-network and relay-agent. The
bootstrap client is for isolated packet testing and must be revoked before rollout.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import tomllib


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def write(path, text, mode=0o644):
    path = Path(path)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), 'w') as f:
        f.write(text)
    path.chmod(mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--subnet', required=True)
    parser.add_argument('--bandwidth-mbps', default='auto',
                        help='Aggregate VPN budget, or auto to measure once before installation')
    args = parser.parse_args()
    host, port_text = args.endpoint.rsplit(':', 1)
    ipaddress.IPv4Address(host)
    port = int(port_text)
    assert 1024 <= port <= 65535
    assert re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', args.interface)
    subnet = ipaddress.IPv4Network(args.subnet)
    assert subnet.prefixlen == 24 and subnet.is_private
    assert os.geteuid() == 0, 'Run as root'
    stage = Path.cwd()
    assert (stage / 'relay-agent').is_file(), 'Stage the binary first'
    for path in ['/etc/relay-node', '/var/lib/relay-node', '/usr/local/bin/relay-agent',
                 '/usr/local/libexec/relay-network', '/etc/systemd/system/relay-network.service',
                 '/etc/systemd/system/relay-agent.service']:
        assert not Path(path).exists(), f'Refusing to replace existing {path}'
    from bandwidth import measure, traffic_config
    if args.bandwidth_mbps == 'auto':
        bandwidth_mbps = measure()['bandwidth_mbps']
    else:
        bandwidth_mbps = int(args.bandwidth_mbps)
        if not 1 <= bandwidth_mbps <= 100_000:
            parser.error('--bandwidth-mbps must be between 1 and 100000')
    routes = json.loads(run('ip', '-j', '-4', 'route'))
    assert any(r.get('dst') == 'default' and r.get('dev') == args.interface for r in routes)
    for route in routes:
        destination = route.get('dst', 'default')
        if destination != 'default':
            assert not subnet.overlaps(ipaddress.IPv4Network(destination, strict=False)), 'Subnet overlap'
    assert subprocess.run(['nft', 'list', 'table', 'inet', 'relay_node'], capture_output=True).returncode != 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('0.0.0.0', port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 18798))
    before = stage / 'before'
    before.mkdir(mode=0o700)
    write(before/'nft.txt', run('nft', 'list', 'ruleset'), 0o600)
    write(before/'routes.json', json.dumps(routes), 0o600)
    write(before/'legacy-pid', run('systemctl', 'show', 'mousevpn-server', '-p', 'MainPID', '--value'), 0o600)
    try:
        owner = pwd.getpwnam('relaynode')
    except KeyError:
        run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'relaynode')
        owner = pwd.getpwnam('relaynode')
    run('install', '-d', '-m', '750', '-o', 'relaynode', '-g', 'relaynode', '/etc/relay-node')
    run('install', '-d', '-m', '700', '-o', 'relaynode', '-g', 'relaynode', '/var/lib/relay-node')
    run('install', '-m', '755', str(stage/'relay-agent'), '/usr/local/bin/relay-agent')
    run('/usr/local/bin/relay-agent', 'generate-example', '--server-config', '/etc/relay-node/server.toml',
        '--client-config', str(stage/'bootstrap-client.toml'), '--server-endpoint', args.endpoint)
    config = Path('/etc/relay-node/server.toml')
    prefix = str(subnet.network_address).rsplit('.', 1)[0]+'.'
    config.write_text(config.read_text().replace('mousevpn0', 'relay0').replace('10.77.0.', prefix).replace('mtu = 1280', 'mtu = 1400') + traffic_config(bandwidth_mbps))
    os.chown(config, owner.pw_uid, owner.pw_gid)
    write('/etc/relay-node/local-admin.token', secrets.token_urlsafe(48), 0o600)
    os.chown('/etc/relay-node/local-admin.token', owner.pw_uid, owner.pw_gid)
    write('/etc/relay-node/relay.nft', f'''table inet relay_node {{
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  oifname "{args.interface}" ip saddr {subnet} masquerade
 }}
 chain mangle {{
  type filter hook forward priority mangle; policy accept;
  iifname "relay0" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
  oifname "relay0" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
 }}
}}
''')
    run('nft', '-c', '-f', '/etc/relay-node/relay.nft')
    Path('/usr/local/libexec').mkdir(exist_ok=True)
    write('/usr/local/libexec/relay-network', f'''#!/bin/sh
set -eu
case "${{1:-}}" in
 start)
  nft list table inet relay_node >/dev/null 2>&1 || nft -f /etc/relay-node/relay.nft
  # Docker may impose its own forwarding rules. Add only our interface/subnet.
  if command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
   iptables -w -C DOCKER-USER -i relay0 -o {args.interface} -s {subnet} -j ACCEPT 2>/dev/null || iptables -w -I DOCKER-USER 1 -i relay0 -o {args.interface} -s {subnet} -j ACCEPT
   iptables -w -C DOCKER-USER -i {args.interface} -o relay0 -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -w -I DOCKER-USER 1 -i {args.interface} -o relay0 -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi
  ;;
 stop)
  if command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
   if iptables -w -C DOCKER-USER -i relay0 -o {args.interface} -s {subnet} -j ACCEPT 2>/dev/null; then iptables -w -D DOCKER-USER -i relay0 -o {args.interface} -s {subnet} -j ACCEPT; fi
   if iptables -w -C DOCKER-USER -i {args.interface} -o relay0 -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then iptables -w -D DOCKER-USER -i {args.interface} -o relay0 -d {subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; fi
  fi
  if nft list table inet relay_node >/dev/null 2>&1; then nft delete table inet relay_node; fi
  ;;
 *) exit 2;;
esac
''', 0o755)
    write('/etc/sysctl.d/90-relay-node.conf', 'net.ipv4.ip_forward=1\n')
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    write('/etc/systemd/system/relay-network.service', '''[Unit]
Description=Private relay forwarding
After=network-online.target docker.service nftables.service
Before=relay-agent.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/relay-network start
ExecStop=/usr/local/libexec/relay-network stop
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
    write('/etc/systemd/system/relay-agent.service', '''[Unit]
Description=Private relay service
After=network-online.target relay-network.service
Wants=network-online.target
Requires=relay-network.service
[Service]
User=relaynode
Group=relaynode
ExecStart=/usr/local/bin/relay-agent --config /etc/relay-node/server.toml
Environment=RELAY_CONTROL_URL=https://mousevpn.space/vpn
Environment=RELAY_NODE_TOKEN_FILE=/etc/relay-node/node.token
Environment=RELAY_DEVICE_STORE=/var/lib/relay-node/devices.toml
Environment=RELAY_TRAFFIC_STORE=/var/lib/relay-node/traffic.sqlite3
Environment=RELAY_ADMIN_TOKEN_FILE=/etc/relay-node/local-admin.token
Environment=MOUSEVPN_ADMIN_LISTEN=127.0.0.1:18798
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
UMask=0077
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
DeviceAllow=/dev/net/tun rw
StateDirectory=relay-node
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
[Install]
WantedBy=multi-user.target
''')
    run('systemd-analyze', 'verify', '/etc/systemd/system/relay-agent.service', '/etc/systemd/system/relay-network.service')
    run('systemctl', 'daemon-reload')
    value = tomllib.loads(config.read_text())
    print(json.dumps({'endpoint':args.endpoint, 'public_key':value['server_public_key'], 'protocol':'morph_balanced', 'enabled':False}))


if __name__ == '__main__':
    main()
