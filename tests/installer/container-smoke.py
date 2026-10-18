#!/usr/bin/env python3
"""Run ONLY inside the disposable privileged systemd fixture, never a real host."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.error
import urllib.request

assert Path('/opt/afs-installer-fixture').read_text().strip() == 'disposable-afs-installer-fixture'
assert Path('/run/systemd/container').read_text().strip() == 'docker'
assert os.geteuid() == 0
REPO = Path('/opt/agent-fileserver')


def run(args, **kw):
    return subprocess.run(args, cwd=REPO, check=True, **kw)


def install(*args):
    run(['./install.sh', '--binary', '/opt/afs-api', '--caddy', '/opt/afs-caddy', *args])


def refused(*args):
    result = subprocess.run(['./install.sh', *args], cwd=REPO, capture_output=True)
    assert result.returncode != 0, 'installer unexpectedly accepted conflicting installation'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get(path, expected):
    try:
        response = urllib.request.urlopen('http://127.0.0.1:8000' + path)
    except urllib.error.HTTPError as e:
        response = e
    assert response.status == expected, (path, response.status)
    return response.read()


install('--mode', 'proxy', '--base-url', 'https://files.example.test', '--namespace', 'fixture')
for unit in ('agent-fileserver-api.service', 'agent-fileserver.service'):
    run(['systemctl', 'is-active', '--quiet', unit])
    run(['systemd-analyze', 'verify', '/etc/systemd/system/' + unit])
run(['curl', '-fsS', '--unix-socket', '/run/agent-fileserver-api/http.sock',
     'http://localhost/_internal/health'], stdout=subprocess.DEVNULL)
run(['systemctl', 'is-active', '--quiet', 'agent-fileserver-healthcheck.timer'])
run(['systemctl', 'start', 'agent-fileserver-healthcheck.service'])
get('/', 404)
get('/_api/v1/me', 401)
get('/mcp', 401)  # route must reach API before anonymous GET/POST gate
request = urllib.request.Request('http://127.0.0.1:8000/mcp', data=b'{}', method='POST')
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as e:
    assert e.code == 401
else:
    raise AssertionError('anonymous MCP POST unexpectedly permitted')
for p in ('/_internal/health', '/credentials/tokens.json', '/policies/example.json', '/.env'):
    get(p, 404)

# Generate fixture-only credentials privately, create a release through the CLI,
# then verify upgrade never rewrites data, policies, registry, or config.
secret = run(['/usr/local/bin/agent-fileserver', 'token', 'create', '--label', 'fixture'],
             capture_output=True).stdout
assert secret.strip()
site = Path('/tmp/afs-fixture-site')
site.mkdir(mode=0o755)
(site / 'index.html').write_text('<h1>installer fixture</h1>')
(site / 'index.html').chmod(0o644)
(site / 'style.css').write_text('body { color: navy; }\n' * 200)
(site / 'style.css').chmod(0o644)
result = run(['/usr/local/bin/agent-fileserver', '--json', str(site)], capture_output=True)
release = json.loads(result.stdout)
get('/' + release['token'] + '/', 200)
assert (Path('/var/lib/agent-fileserver/public') / release['token'] / 'style.css.br').is_file()
# Exercise brotli from the sandboxed API worker, not only the local CLI.
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w') as tar:
    for name in ('index.html', 'style.css'):
        data = (site / name).read_bytes()
        info = tarfile.TarInfo('site/' + name)
        info.size, info.mode = len(data), 0o644
        tar.addfile(info, io.BytesIO(data))
boundary = 'afs-disposable-fixture-boundary'
body = (f'--{boundary}\r\nContent-Disposition: form-data; name="metadata"\r\n'
        'Content-Type: application/json\r\n\r\n{"label":"fixture-api"}\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="artifact"; filename="site.tar"\r\n'
        'Content-Type: application/octet-stream\r\n\r\n').encode()
body += archive.getvalue() + f'\r\n--{boundary}--\r\n'.encode()
request = urllib.request.Request('http://127.0.0.1:8000/_api/v1/releases', data=body, method='POST',
    headers={'Authorization': 'Bearer ' + secret.decode().strip(),
             'Content-Type': 'multipart/form-data; boundary=' + boundary,
             'Idempotency-Key': 'installer-fixture-idempotency-0001'})
with urllib.request.urlopen(request) as response:
    assert response.status == 201
    api_release = json.load(response)
assert (Path('/var/lib/agent-fileserver/public') / api_release['token'] / 'style.css.br').is_file()
root = Path('/var/lib/agent-fileserver')
protected = {p: sha(p) for p in root.rglob('*') if p.is_file()}
protected[Path('/etc/agent-fileserver/environment')] = sha(Path('/etc/agent-fileserver/environment'))
refused('--base-url', 'https://files.example.test')
refused('--upgrade', '--base-url', 'https://different.example.test')
install('--upgrade')
assert all(sha(p) == digest for p, digest in protected.items())
get('/' + release['token'] + '/', 200)
config = Path('/etc/agent-fileserver/Caddyfile')
original = config.read_bytes()
config.write_bytes(original + b'\n# operator edit\n')
refused('--upgrade')
assert config.read_bytes() == original + b'\n# operator edit\n'
config.write_bytes(original)
for unit in ('agent-fileserver-api.service', 'agent-fileserver.service'):
    run(['systemctl', 'is-active', '--quiet', unit])
api_pid = run(['systemctl', 'show', 'agent-fileserver-api.service', '-p', 'MainPID', '--value'],
              capture_output=True, text=True).stdout.strip()
status = Path('/proc/' + api_pid + '/status').read_text()
assert 'CapEff:\t0000000000000000' in status
assert 'CapBnd:\t0000000000000000' in status
assert os.readlink('/proc/' + api_pid + '/ns/net') != os.readlink('/proc/1/ns/net')
options = run(['nsenter', '--target', api_pid, '--mount', '--', 'findmnt', '-no', 'OPTIONS',
               '/var/lib/agent-fileserver/credentials'], capture_output=True, text=True).stdout
assert 'ro' in options.strip().split(',')
web_pid = run(['systemctl', 'show', 'agent-fileserver.service', '-p', 'MainPID', '--value'],
              capture_output=True, text=True).stdout.strip()
mountinfo = Path('/proc/' + web_pid + '/mountinfo').read_text()
for private in ('staging', 'manifests', 'trash', 'policies', 'credentials', 'incoming', 'api-state'):
    assert '/var/lib/agent-fileserver/' + private in mountinfo, ('private mount mask missing', private)
run(['nsenter', '--target', web_pid, '--mount', '--', '/usr/bin/test', '!', '-e',
     '/var/lib/agent-fileserver/credentials/tokens.json'])
assert Path('/var/log/agent-fileserver').stat().st_mode & 0o777 == 0o700
assert Path('/var/log/agent-fileserver/access.json').stat().st_mode & 0o777 == 0o600
# A stopped API must stay stopped when the timer probes the still-active frontend.
run(['systemctl', 'stop', 'agent-fileserver-api.service'])
run(['systemctl', 'start', 'agent-fileserver-healthcheck.service'])
# Restarting the active frontend must not pull a deliberately stopped API back in.
run(['systemctl', 'try-restart', 'agent-fileserver.service'])
assert subprocess.run(['systemctl', 'is-active', '--quiet', 'agent-fileserver-api.service']).returncode != 0
run(['systemctl', 'start', 'agent-fileserver-api.service'])
print('Fresh proxy install, Unix health/auth/static paths, explicit upgrade/data preservation and refusals passed.')
print('Direct public ACME/DNS/443 and real-client 100MiB behavior are NOT covered by this fixture.')
