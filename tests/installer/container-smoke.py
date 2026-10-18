#!/usr/bin/env python3
"""Run ONLY inside the disposable privileged systemd fixture, never a real host."""
import base64
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
get('/_api/v1/me', 404)  # MCP is the only management interface
get('/mcp', 401)  # route must reach API before anonymous GET/POST gate
request = urllib.request.Request('http://127.0.0.1:8000/mcp', data=b'{}', method='POST')
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as e:
    assert e.code == 401
else:
    raise AssertionError('anonymous MCP POST unexpectedly permitted')
for p in ('/_internal/health', '/_api/v1/releases', '/credentials/tokens.json', '/policies/example.json', '/.env'):
    get(p, 404)

# Generate fixture-only credentials privately and create a release through MCP
# (the only management interface), then verify upgrade never rewrites data,
# policies, registry, or config.
secret = run(['/usr/local/bin/agent-fileserver', 'token', 'create', '--label', 'fixture'],
             capture_output=True).stdout.decode().strip()
assert secret
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w') as tar:
    for name, data in (('index.html', b'<h1>installer fixture</h1>'),
                       ('style.css', b'body { color: navy; }\n' * 200)):
        info = tarfile.TarInfo('site/' + name)
        info.size, info.mode = len(data), 0o644
        tar.addfile(info, io.BytesIO(data))


def mcp_tool(name, arguments, header='Authorization', value='Bearer ' + secret):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': name, 'arguments': arguments}}).encode()
    request = urllib.request.Request('http://127.0.0.1:8000/mcp', data=body, method='POST', headers={
        header: value, 'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18'})
    with urllib.request.urlopen(request) as response:
        assert response.status == 200
        result = json.load(response)['result']
    assert not result.get('isError'), name
    return json.loads(result['content'][0]['text'])


release = mcp_tool('publish_archive', {'label': 'fixture-mcp', 'idempotency_key': 'installer-fixture-idempotency-0001',
                                       'archive_base64': base64.b64encode(archive.getvalue()).decode()})
get('/' + release['token'] + '/', 200)
# Brotli runs inside the sandboxed API worker.
assert (Path('/var/lib/agent-fileserver/public') / release['token'] / 'style.css.br').is_file()
# Claude-style static key header authenticates the same way.
assert mcp_tool('server_info', {}, header='X-Auth-Token', value=secret)['agent'] == 'fixture'
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
