#!/usr/bin/env python3
"""Native installer. Rendering/preflight/validation are deliberately rootless.

Only apply() changes the host; its checks precede downloads/builds and all writes.
The manifest is an ownership/checksum boundary, not a migration mechanism.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from fetch_dependencies import caddy as fetch_caddy, go as fetch_go, GO_VERSION, CADDY_VERSION

REPO = Path(__file__).resolve().parent.parent
ETC = Path('/etc/agent-fileserver')
DATA = Path('/var/lib/agent-fileserver')
CADDY_DATA = Path('/var/lib/agent-fileserver-caddy')
LOGS = Path('/var/log/agent-fileserver')
LIB = Path('/usr/local/libexec')
BIN = Path('/usr/local/bin')
UNITS = Path('/etc/systemd/system')
API_UNIT = 'agent-fileserver-api.service'
WEB_UNIT = 'agent-fileserver.service'
HEALTH_UNIT = 'agent-fileserver-healthcheck.service'
HEALTH_TIMER = 'agent-fileserver-healthcheck.timer'
HEALTH_BINARY = LIB / 'agent-fileserver-healthcheck'
MANIFEST = ETC / 'install.json'
API_BINARY = LIB / 'agent-fileserver'
WEB_BINARY = LIB / 'agent-fileserver-caddy'
API_USER, WEB_USER = 'afs-api', 'afs-caddy'
DIRECTORIES = [ETC, DATA, CADDY_DATA, LOGS]
CONFIG_KEYS = ('base_url', 'namespace', 'mode', 'listen', 'trusted_proxy', 'healthcheck')


def run(args, **kwargs):
    try:
        return subprocess.run([str(x) for x in args], check=True, **kwargs)
    except PermissionError as e:
        raise ValueError(f'cannot execute {args[0]}: {e}; if temporary downloads/builds are on a noexec filesystem, set TMPDIR to a private directory on an executable filesystem') from e


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def real_path(path):
    """Never follow a symlink, including in an ancestor of a managed target."""
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise ValueError(f'refusing symlinked installation path: {p}')


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--base-url', help='public HTTPS origin, e.g. https://files.example.com (no path)')
    p.add_argument('--namespace', help='API namespace (default: default)')
    p.add_argument('--mode', choices=['direct', 'proxy'], help='direct: automatic HTTPS (default); proxy: trusted HTTPS frontend')
    p.add_argument('--listen', help='proxy-only origin listener, e.g. :8000 or 127.0.0.1:8000 (default: :8000)')
    p.add_argument('--trusted-proxy', action='append', help='proxy-only exact IP/CIDR; repeat for actual frontend addresses; never inferred')
    p.add_argument('--no-healthcheck', dest='healthcheck', action='store_false', default=None,
                   help='do not enable the default bounded health timer (fresh installs only)')
    p.add_argument('--upgrade', action='store_true', help='explicitly replace only checksum-unchanged managed files; preserve all state/credentials')
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--render-only', action='store_true', help='render into a new/empty directory; no root, downloads, or host changes')
    modes.add_argument('--validate-only', action='store_true', help='render, build/find dependencies, validate Caddy/systemd only; no host changes')
    modes.add_argument('--check-host', action='store_true', help='check ownership/refusals only; rootless, no writes/downloads')
    p.add_argument('--output-dir', type=Path, help='new/empty render directory; default: private temporary directory')
    p.add_argument('--binary', type=Path, help='prebuilt native API binary (otherwise build current checkout)')
    p.add_argument('--caddy', type=Path, help='native Caddy binary; otherwise use installed Caddy or verified pinned download')
    p.add_argument('--download-deps', action='store_true', help='allow SHA-verified official Go/Caddy downloads when missing')
    a = p.parse_args(argv)
    if a.output_dir and not (a.render_only or a.validate_only):
        p.error('--output-dir requires --render-only or --validate-only')
    return a


def configuration(a, previous=None):
    previous = previous or {}
    c = {k: getattr(a, k) if getattr(a, k) is not None else previous.get(k) for k in CONFIG_KEYS}
    c['healthcheck'] = True if c['healthcheck'] is None else c['healthcheck']
    c['namespace'] = c['namespace'] or 'default'
    c['mode'] = c['mode'] or 'direct'
    c['trusted_proxy'] = c['trusted_proxy'] or []
    if not c['base_url']:
        raise ValueError('--base-url is required for a fresh installation')
    u = urlsplit(c['base_url'])
    if (u.scheme != 'https' or not u.hostname or u.username or u.password or
            u.path not in ('', '/') or '?' in c['base_url'] or '#' in c['base_url'] or re.search(r'[^\x21-\x7e]', c['base_url'])):
        raise ValueError('--base-url must be an HTTPS origin without credentials, path, query, fragment, or whitespace')
    # Keep both Caddyfile and systemd environment syntax injection-free.
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', u.hostname):
        raise ValueError('base URL hostname must be a DNS name (IDNs must use punycode)')
    if '..' in u.hostname or any(len(x) > 63 or x.startswith('-') or x.endswith('-') for x in u.hostname.split('.')):
        raise ValueError('invalid DNS hostname')
    port = u.port  # deliberately validates numeric/range errors
    c['base_url'] = 'https://' + u.hostname.lower() + (f':{port}' if port and port != 443 else '')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', c['namespace']):
        raise ValueError('namespace must be 1..64 ASCII letters, digits, underscores or hyphens')
    if c['mode'] == 'direct':
        if c['listen'] or c['trusted_proxy']:
            raise ValueError('--listen/--trusted-proxy require --mode proxy; direct TLS never trusts forwarded headers')
        if port not in (None, 443) or '.' not in u.hostname or u.hostname.endswith('.localhost'):
            raise ValueError('direct mode requires a public DNS name on standard HTTPS port 443')
        try:
            ipaddress.ip_address(u.hostname)
        except ValueError:
            pass
        else:
            raise ValueError('direct automatic public HTTPS requires a DNS name, not an IP address')
    else:
        c['listen'] = c['listen'] or ':8000'
        m = re.fullmatch(r'(?:(127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\[::\]))?:(\d{1,5})', c['listen'])
        if not m or not 1024 <= int(m[2]) <= 65535:
            raise ValueError('proxy listener must be :PORT or explicit loopback/wildcard IP:PORT, port 1024..65535')
        c['trusted_proxy'] = [str(ipaddress.ip_network(x, strict=True)) for x in c['trusted_proxy']]
        if any(ipaddress.ip_network(x).prefixlen == 0 for x in c['trusted_proxy']):
            raise ValueError('blanket trusted-proxy /0 is forbidden')
    if previous and c != previous:
        raise ValueError('upgrade configuration differs: preserve base URL/namespace/mode/listen/proxy CIDRs/health setting; review configuration changes separately')
    return c


def rendered(c):
    caddy = (REPO / 'deploy/Caddyfile.template').read_text()
    trust = ''
    if c['trusted_proxy']:
        trust = ('\t\ttrusted_proxies static ' + ' '.join(c['trusted_proxy']) +
                 '\n\t\ttrusted_proxies_strict\n\t\tclient_ip_headers X-Forwarded-For')
    caddy = caddy.replace('@AUTO_HTTPS@\n', '\tauto_https off\n' if c['mode'] == 'proxy' else '')
    caddy = caddy.replace('@TRUSTED_PROXIES@\n', trust + '\n' if trust else '')
    caddy = caddy.replace('@SITE@', c['listen'] if c['mode'] == 'proxy' else c['base_url'][8:])
    web = (REPO / 'deploy/agent-fileserver.service.template').read_text()
    web = web.replace('@CAPABILITIES@', 'CAP_NET_BIND_SERVICE' if c['mode'] == 'direct' else '')
    environment = (f'FSERVER_ROOT={DATA}\nFSERVER_BASE_URL={c["base_url"]}\n'
                   f'FSERVER_NAMESPACE={c["namespace"]}\nFSERVER_TOKEN_FILE={DATA}/credentials/tokens.json\n'
                   f'FSERVER_MODE={c["mode"]}\nFSERVER_LISTEN={c["listen"] or ""}\n')
    wrapper = f'''#!/bin/sh
# Root-owned local administration. No service user receives sudo access.
set -eu
if [ "$(id -u)" != 0 ]; then
    echo "Run sudo agent-fileserver ... (local administration only)" >&2
    exit 1
fi
set -a
. {ETC}/environment
set +a
exec /usr/sbin/runuser -u {API_USER} -g {WEB_USER} -- /usr/bin/env \\
    FSERVER_ROOT="$FSERVER_ROOT" FSERVER_BASE_URL="$FSERVER_BASE_URL" \\
    FSERVER_NAMESPACE="$FSERVER_NAMESPACE" FSERVER_TOKEN_FILE="$FSERVER_TOKEN_FILE" \\
    {API_BINARY} "$@"
'''
    return {ETC / 'Caddyfile': (caddy, 0o644), ETC / 'environment': (environment, 0o600),
            UNITS / API_UNIT: ((REPO / 'deploy/agent-fileserver-api.service').read_text(), 0o644),
            UNITS / WEB_UNIT: (web, 0o644), BIN / 'agent-fileserver': (wrapper, 0o755),
            UNITS / HEALTH_UNIT: ((REPO / 'deploy' / HEALTH_UNIT).read_text(), 0o644),
            UNITS / HEALTH_TIMER: ((REPO / 'deploy' / HEALTH_TIMER).read_text(), 0o644),
            HEALTH_BINARY: ((REPO / 'deploy/agent-fileserver-healthcheck').read_text(), 0o755),
            BIN / 'agent-fileserver-token': ('#!/bin/sh\nset -eu\nexec /usr/local/bin/agent-fileserver token "$@"\n', 0o755)}


def host_path(root, path):
    return root / str(path).lstrip('/')


def preflight(a, root=Path('/')):
    """Read-only refusal checks; root is injectable only for fixture unit tests."""
    paths = [*DIRECTORIES, MANIFEST, API_BINARY, WEB_BINARY, BIN / 'agent-fileserver',
             BIN / 'agent-fileserver-token', UNITS / API_UNIT, UNITS / WEB_UNIT, UNITS / HEALTH_UNIT, UNITS / HEALTH_TIMER, HEALTH_BINARY,
             Path('/run/agent-fileserver-api')]
    for p in paths:
        real_path(host_path(root, p))
    manifest = host_path(root, MANIFEST)
    if not a.upgrade:
        for p in paths:
            if host_path(root, p).exists():
                raise ValueError(f'refusing existing unmanaged installation path: {p}; --upgrade requires installer manifest')
        if root == Path('/'):
            for user in (API_USER, WEB_USER):
                try:
                    pwd.getpwnam(user)
                except KeyError:
                    pass
                else:
                    raise ValueError(f'refusing existing service account: {user}')
                try:
                    grp.getgrnam(user)
                except KeyError:
                    pass
                else:
                    raise ValueError(f'refusing existing service group: {user}')
        return None
    if not manifest.is_file():
        raise ValueError('--upgrade requires a previous managed install.json; no legacy/public-policy migration is performed')
    if root == Path('/') and (manifest.stat().st_uid != 0 or stat.S_IMODE(manifest.stat().st_mode) != 0o600):
        raise ValueError('install.json must remain root-owned mode 0600')
    state = json.loads(manifest.read_text())
    if state.get('format') != 1 or not isinstance(state.get('files'), dict):
        raise ValueError('unrecognized managed installation manifest')
    allowed = set(rendered(configuration(a, state['configuration']))) | {API_BINARY, WEB_BINARY}
    if set(state['files']) != {str(p) for p in allowed}:
        raise ValueError('incomplete or unexpected managed file inventory')
    for name, record in state['files'].items():
        path = host_path(root, Path(name))
        real_path(path)
        if (not path.is_file() or digest(path) != record['sha256'] or
                stat.S_IMODE(path.stat().st_mode) != record['mode'] or
                (root == Path('/') and path.stat().st_uid != 0)):
            raise ValueError(f'refusing overwrite of missing/changed/unmanaged file: {name}')
    for p in DIRECTORIES:
        if not host_path(root, p).is_dir():
            raise ValueError(f'managed state directory missing: {p}')
    if root == Path('/'):
        for user, identity in state['identities'].items():
            info = pwd.getpwnam(user)
            if [info.pw_uid, info.pw_gid] != identity or info.pw_uid == 0:
                raise ValueError(f'service identity changed: {user}')
        for p in DIRECTORIES:
            if host_path(root, p).stat().st_uid != state['directories'][str(p)]:
                raise ValueError(f'managed directory owner changed: {p}')
    return state


def write_render(directory, files):
    real_path(directory)
    if directory.exists() and (directory.is_symlink() or not directory.is_dir() or any(directory.iterdir())):
        raise ValueError('--output-dir must be a new or empty directory')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for target, (text, mode) in files.items():
        out = directory / str(target).lstrip('/')
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        out.chmod(mode)


def prerequisites():
    required = ['curl', 'brotli', 'systemctl', 'systemd-analyze', 'groupadd', 'useradd', 'runuser']
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise ValueError('missing prerequisites: ' + ', '.join(missing) +
                         '; install from official Ubuntu/Debian repositories: apt-get update && apt-get install ca-certificates curl brotli python3 systemd passwd util-linux')


def dependencies(a, work):
    api = a.binary.resolve() if a.binary else None
    web = a.caddy.resolve() if a.caddy else None
    if web is None:
        found = shutil.which('caddy')
        if a.upgrade and WEB_BINARY.is_file():
            web = WEB_BINARY
        elif found:
            web = Path(found).resolve()
        elif WEB_BINARY.is_file():
            web = WEB_BINARY
        elif a.download_deps:
            web = fetch_caddy(work)
        else:
            raise ValueError('Caddy missing: provide --caddy PATH or --download-deps (official SHA-verified release)')
    if api is None:
        go = shutil.which('go')
        if go:
            version = run([go, 'version'], capture_output=True, text=True).stdout
            match = re.search(r'go(\d+)\.(\d+)', version)
            required = re.search(r'^go (\d+)\.(\d+)', (REPO / 'go.mod').read_text(), re.M)
            if not match or tuple(map(int, match.groups())) < tuple(map(int, required.groups())):
                go = None
        if not go:
            if not a.download_deps:
                raise ValueError('compatible Go missing: provide --binary PATH or --download-deps')
            go = fetch_go(work)
        api = work / 'agent-fileserver'
        env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0')
        run([go, 'build', '-mod=readonly', '-trimpath', '-o', api, '.'], cwd=REPO, env=env)
    for path in (api, web):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f'not an executable regular file: {path}; if a temporary filesystem is noexec, set TMPDIR to a private directory on an executable filesystem')
    run([web, 'version'])
    return api, web


def validate(directory, api, web):
    """Caddy validation provisions log/storage modules; remap them to fixtures.

    Never validate the final absolute Caddyfile during rootless validation: doing
    so can open real logs. Units retain sandbox settings; only ExecStart paths
    are remapped to executables that actually exist before installation.
    """
    with tempfile.TemporaryDirectory(prefix='afs-validate-') as name:
        work = Path(name)
        caddy = (directory / str(ETC / 'Caddyfile').lstrip('/')).read_text()
        for p in (DATA, CADDY_DATA, LOGS):
            (work / p.name).mkdir(exist_ok=True)
            caddy = caddy.replace(str(p), str(work / p.name))
        config = work / 'Caddyfile'
        config.write_text(caddy)
        run([web, 'validate', '--config', config, '--adapter', 'caddyfile'])
        health_script = directory / str(HEALTH_BINARY).lstrip('/')
        # Render directories may live on noexec /tmp. Check shell syntax without
        # executing a health probe; verify the existing interpreter, not a temp
        # script's mount flags. Production ExecStart remains the installed helper.
        run(['/bin/sh', '-n', health_script])
        unit_dir = work / 'units'
        unit_dir.mkdir()
        for unit in (API_UNIT, WEB_UNIT, HEALTH_UNIT, HEALTH_TIMER):
            text = (directory / str(UNITS / unit).lstrip('/')).read_text()
            text = text.replace('ExecStart=' + str(WEB_BINARY) + ' ', 'ExecStart=' + str(web) + ' ')
            text = text.replace('ExecStart=' + str(API_BINARY) + ' ', 'ExecStart=' + str(api) + ' ')
            text = text.replace('ExecStart=' + str(HEALTH_BINARY) + '\n',
                                'ExecStart=/bin/sh ' + str(health_script) + '\n')
            (unit_dir / unit).write_text(text)
        run(['systemd-analyze', 'verify', unit_dir / API_UNIT, unit_dir / WEB_UNIT, unit_dir / HEALTH_UNIT, unit_dir / HEALTH_TIMER])


def atomic_write(path, data, mode):
    # Same-directory rename; no in-place executable or config truncation.
    fd, name = tempfile.mkstemp(prefix='.afs-install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply(a, c, files, api, web, previous):
    if os.geteuid() != 0:
        raise ValueError('installation requires root; use --render-only/--validate-only/--check-host without root')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('a booted systemd host is required (not a plain Docker container)')
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=(?:"?)(?:ubuntu|debian)(?:"?)$', os_release, re.M):
        raise ValueError('supported native targets: Ubuntu/Debian Linux with systemd')
    # Recheck after potentially slow build/downloads, immediately before changes.
    preflight(a)
    if not previous:
        ports = [80, 443] if c['mode'] == 'direct' else [int(c['listen'].rsplit(':', 1)[1])]
        for port in ports:
            for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as probe:
                        if family == socket.AF_INET6:
                            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        probe.bind((address, port))
                except OSError as e:
                    if family == socket.AF_INET6 and e.errno in (97, 99):
                        continue
                    raise ValueError(f'listener port {port} unavailable; stop conflicting services explicitly: {e}')
    payloads = {p: (text.encode(), mode) for p, (text, mode) in files.items()}
    payloads[API_BINARY] = (api.read_bytes(), 0o755)
    payloads[WEB_BINARY] = (web.read_bytes(), 0o755)
    was_active = {}
    backup = {}
    if previous:
        for unit in (HEALTH_TIMER, WEB_UNIT, API_UNIT):
            was_active[unit] = subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0
        backup = {p: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in payloads}
        # Never rewrite credentials or recursively chmod/chown existing data.
        run(['systemctl', 'stop', HEALTH_TIMER, HEALTH_UNIT, WEB_UNIT, API_UNIT])
    else:
        for user in (WEB_USER, API_USER):
            run(['groupadd', '--system', user])
            run(['useradd', '--system', '--gid', user, '--home-dir', '/nonexistent',
                 '--no-create-home', '--shell', '/usr/sbin/nologin', user])
        for p, user, group, mode in [(ETC, 'root', 'root', 0o755), (DATA, API_USER, WEB_USER, 0o755),
                                      (CADDY_DATA, WEB_USER, WEB_USER, 0o700), (LOGS, WEB_USER, WEB_USER, 0o700)]:
            p.mkdir(mode=mode)
            p.chmod(mode)
            shutil.chown(p, user, group)
        for name in ('public', 'staging', 'manifests', 'trash', 'policies', 'incoming', 'api-state', 'credentials'):
            p = DATA / name
            p.mkdir(mode=0o755 if name == 'public' else 0o700)
            shutil.chown(p, API_USER, WEB_USER)
        # Empty registry grants nobody access. Do not create/print a bearer key.
        registry = DATA / 'credentials/tokens.json'
        atomic_write(registry, b'{"version":1,"tokens":[]}\n', 0o600)
        shutil.chown(registry, API_USER, WEB_USER)
    try:
        for p, (content, mode) in payloads.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(p, content, mode)
        run(['systemctl', 'daemon-reload'])
        if previous:
            for unit in (API_UNIT, WEB_UNIT, HEALTH_TIMER):
                if was_active[unit]:
                    run(['systemctl', 'start', unit])
        else:
            run(['systemctl', 'enable', '--now', API_UNIT, WEB_UNIT])
            if c['healthcheck']:
                run(['systemctl', 'enable', '--now', HEALTH_TIMER])
        # Caddy Type=notify and API ExecStartPost healthcheck make start synchronous.
        state = {'format': 1, 'configuration': c,
                 'files': {str(p): {'sha256': digest(p), 'mode': mode} for p, (_, mode) in payloads.items()},
                 'identities': {u: [pwd.getpwnam(u).pw_uid, pwd.getpwnam(u).pw_gid] for u in (API_USER, WEB_USER)},
                 'directories': {str(p): p.stat().st_uid for p in DIRECTORIES}}
        atomic_write(MANIFEST, (json.dumps(state, indent=2) + '\n').encode(), 0o600)
    except Exception:
        if previous:
            subprocess.run(['systemctl', 'stop', HEALTH_TIMER, HEALTH_UNIT, WEB_UNIT, API_UNIT])
            for p, (content, mode) in backup.items():
                atomic_write(p, content, mode)
            subprocess.run(['systemctl', 'daemon-reload'])
            for unit in (API_UNIT, WEB_UNIT, HEALTH_TIMER):
                if was_active.get(unit):
                    subprocess.run(['systemctl', 'start', unit])
            print('Upgrade failed; restored prior binaries/configuration. No release/credential data was replaced.', file=sys.stderr)
        else:
            subprocess.run(['systemctl', 'stop', HEALTH_TIMER, HEALTH_UNIT, WEB_UNIT, API_UNIT])
            print('Fresh installation failed after host changes; partial paths retained for operator review. No automatic deletion.', file=sys.stderr)
        raise
    print(f'Installed {c["base_url"]} ({c["mode"]}); API /_api/v1, MCP /mcp, namespace {c["namespace"]}.')
    print('Create a named key separately: sudo agent-fileserver token create --label my-agent')
    print('The command prints the secret once: use a private terminal/file, never a build log.')


def main(argv=None):
    a = parse(argv)
    # Render-only on a fresh checkout deliberately ignores any live installation.
    previous = None
    if a.upgrade or not (a.render_only or a.validate_only):
        previous = preflight(a)
    c = configuration(a, previous['configuration'] if previous else None)
    if a.check_host:
        prerequisites()
        print('Host preflight OK; nothing changed.')
        return
    files = rendered(c)
    directory = a.output_dir or Path(tempfile.mkdtemp(prefix='agent-fileserver-render-'))
    write_render(directory, files)
    print(f'Rendered: {directory}', flush=True)
    if a.render_only:
        return
    if not a.validate_only and os.geteuid() != 0:
        raise ValueError('installation requires root; use --validate-only for a rootless preflight')
    prerequisites()
    with tempfile.TemporaryDirectory(prefix='agent-fileserver-build-') as name:
        api, web = dependencies(a, Path(name))
        validate(directory, api, web)
        if a.validate_only:
            print('Caddy and systemd validation passed; no installation/activation performed.')
            return
        apply(a, c, files, api, web, previous)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as e:
        print(f'install: {e}', file=sys.stderr)
        sys.exit(1)
