#!/usr/bin/env python3
from pathlib import Path
import subprocess

p=Path('/opt/lucky/Caddyfile')
before=p.read_text()
if 'handle_path /vpn/*' in before: raise SystemExit('Routes already exist; inspect before changing')
snippet=Path('/tmp/relay-rollout-20261001/caddy-routes.txt').read_text()
marker='\t# Тап-Лапка:'
position=before.index(marker)
p.write_text(before[:position]+'\n'+snippet+'\n'+before[position:])
try:
    subprocess.run(['docker','exec','la-caddy','caddy','validate','--config','/etc/caddy/Caddyfile'],check=True)
    subprocess.run(['docker','exec','la-caddy','caddy','reload','--config','/etc/caddy/Caddyfile'],check=True)
except Exception:
    p.write_text(before)
    subprocess.run(['docker','exec','la-caddy','caddy','reload','--config','/etc/caddy/Caddyfile'])
    raise
print('HTTPS routes loaded without restarting the existing proxy.')
