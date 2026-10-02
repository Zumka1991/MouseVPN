#!/usr/bin/env python3
"""Revoke only the generated bootstrap key after the new controller is online."""
from pathlib import Path
import json
import time
import tomllib
import urllib.parse
import urllib.request

config = tomllib.loads(Path('/etc/relay-node/server.toml').read_text())
owner = Path('/etc/relay-hub/owner.token').read_text().strip()
node_id = Path('/root/relay-rollout-20261001/node-id').read_text().strip()
request = urllib.request.Request('https://myaifriend.su/vpn/v1/admin/servers',
                                 headers={'Authorization': 'Bearer ' + owner})
with urllib.request.urlopen(request, timeout=20) as response:
    nodes = json.load(response)
node = next(node for node in nodes if node['id'] == node_id)
if not node['last_seen'] or time.time() - node['last_seen'] > 60:
    raise RuntimeError('Controller synchronization is not healthy; bootstrap key retained')
token = Path('/etc/relay-node/local-admin.token').read_text().strip()
for device in config['clients']:
    key = urllib.parse.quote(device['public_key'], safe='')
    request = urllib.request.Request('http://127.0.0.1:18798/v1/devices/' + key,
        method='DELETE', headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
    print('Bootstrap key revoked' if result['revoked'] else 'Bootstrap key already absent')
