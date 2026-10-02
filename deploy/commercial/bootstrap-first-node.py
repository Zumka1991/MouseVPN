#!/usr/bin/env python3
"""Initialize a new empty node on the inventoried first VPS. Never print credentials."""
from pathlib import Path
import os, secrets, subprocess, pwd, json, urllib.request, tomllib, urllib.parse

def run(*args): subprocess.run(args, check=True)
def private(path, text, user):
    path = Path(path)
    if path.exists():
        if path.stat().st_mode & 0o077: raise RuntimeError('Existing credential has unsafe permissions')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file: file.write(text)
    account = pwd.getpwnam(user); os.chown(path, account.pw_uid, account.pw_gid)

staged = Path('/tmp/relay-rollout-20261001')
for name in ['relay-hub','relay-agent','hub.toml.example','index.html','style.css','app.js','releases.json','MouseVPN-0.2.0-android.apk','relay-network','relay.nft','relay-hub.service','relay-network.service','relay-agent.service']:
    if not (staged/name).is_file(): raise RuntimeError('Incomplete upload: '+name)
for user in ['relayhub', 'relaynode']:
    try: pwd.getpwnam(user)
    except KeyError: run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', user)
for directory, user in [('/etc/relay-hub','relayhub'),('/etc/relay-node','relaynode')]:
    run('install','-d','-m','750','-o',user,'-g',user,directory)
run('install','-d','-m','700','-o','relayhub','-g','relayhub','/var/lib/relay-hub')
run('install','-d','-m','700','-o','relaynode','-g','relaynode','/var/lib/relay-node')
for binary in ['relay-hub','relay-agent']: run('install','-m','755',str(staged/binary),'/usr/local/bin/'+binary)
private('/etc/relay-hub/owner.token',secrets.token_urlsafe(48),'relayhub')
private('/etc/relay-node/local-admin.token',secrets.token_urlsafe(48),'relaynode')
private('/etc/relay-hub/hub.toml',(staged/'hub.toml.example').read_text(),'relayhub')
run('install','-d','-m','755','-o','relayhub','-g','relayhub','/var/lib/relay-hub/public/downloads')
for name in ['index.html','style.css','app.js','releases.json']:
    run('install','-m','644','-o','relayhub','-g','relayhub',str(staged/name),'/var/lib/relay-hub/public/'+name)
run('install','-m','644','-o','relayhub','-g','relayhub',str(staged/'MouseVPN-0.2.0-android.apk'),'/var/lib/relay-hub/public/downloads/MouseVPN-0.2.0-android.apk')
run('/usr/local/bin/relay-agent','generate-example','--server-config','/etc/relay-node/server.toml','--client-config','/root/relay-rollout-20261001/rescue-client.toml','--server-endpoint','138.124.244.42:51821')
p = Path('/etc/relay-node/server.toml')
p.write_text(p.read_text().replace('mousevpn0','relay0').replace('10.77.0.','10.78.0.').replace('mtu = 1280','mtu = 1400'))
account = pwd.getpwnam('relaynode'); os.chown(p,account.pw_uid,account.pw_gid)
run('install','-m','644',str(staged/'relay.nft'),'/etc/relay-node/relay.nft')
run('install','-d','-m','755','/usr/local/libexec')
run('install','-m','755',str(staged/'relay-network'),'/usr/local/libexec/relay-network')
run('nft','-c','-f','/etc/relay-node/relay.nft')
for name in ['relay-hub.service','relay-network.service','relay-agent.service']:
    run('install','-m','644',str(staged/name),'/etc/systemd/system/'+name)
run('systemctl','daemon-reload')
run('systemctl','enable','--now','relay-hub.service')
print('Hub installed; node will start after HTTPS proxy validation.')
