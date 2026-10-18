#!/usr/bin/env python3
"""Rootless installer tests; no systemctl activation or host writes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
import install as installer
from fetch_dependencies import checksum


class InstallerTests(unittest.TestCase):
    def args(self, *args):
        return installer.parse(list(args))

    def config(self, *args):
        return installer.configuration(self.args('--base-url', 'https://files.example.com', *args))

    def fixture(self, root):
        c = self.config()
        records = {}
        files = installer.rendered(c)
        files[installer.API_BINARY] = ('fake API executable', 0o755)
        files[installer.WEB_BINARY] = ('fake Caddy executable', 0o755)
        for p, (text, mode) in files.items():
            target = installer.host_path(root, p)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            target.chmod(mode)
            records[str(p)] = {'sha256': installer.digest(target), 'mode': mode}
        for p in installer.DIRECTORIES:
            installer.host_path(root, p).mkdir(parents=True, exist_ok=True)
        marker = {'format': 1, 'configuration': c, 'files': records}
        installer.host_path(root, installer.MANIFEST).write_text(json.dumps(marker))
        return marker

    def test_direct_security(self):
        files = installer.rendered(self.config())
        caddy = files[installer.ETC / 'Caddyfile'][0]
        self.assertIn('files.example.com {', caddy)
        self.assertNotIn('auto_https off', caddy)
        self.assertNotIn('trusted_proxies', caddy)
        self.assertIn('max_size 140MiB', caddy)
        self.assertLess(caddy.index('/mcp /mcp/*'), caddy.index('@write'))
        self.assertLess(caddy.index('forward_auth'), caddy.index('file_server'))
        self.assertIn('roll_keep 14', caddy)
        self.assertIn('mode 0600', caddy)
        self.assertNotIn('/home/', caddy)
        self.assertNotIn('browse', caddy)
        self.assertIn('respond @private "Not Found" 404', caddy)
        web = files[installer.UNITS / installer.WEB_UNIT][0]
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE', web)
        self.assertIn('ReadOnlyPaths=/var/lib/agent-fileserver', web)
        self.assertNotIn('Wants=network-online.target agent-fileserver-api.service', web)
        self.assertNotIn('Requires=agent-fileserver-api.service', web)
        for private in ('credentials', 'policies', 'staging', 'manifests', 'trash', 'incoming', 'api-state'):
            self.assertIn('/var/lib/agent-fileserver/' + private, web)
        api = files[installer.UNITS / installer.API_UNIT][0]
        for setting in ('PrivateNetwork=true', 'ProtectHome=true', 'RestrictAddressFamilies=AF_UNIX',
                        'CapabilityBoundingSet=\n', 'AmbientCapabilities=\n', 'MemoryMax=1536M',
                        'Environment=GOMEMLIMIT=512MiB', 'ReadOnlyPaths=/var/lib/agent-fileserver/credentials'):
            self.assertIn(setting, api)
        self.assertNotIn('migrate-policies', '\n'.join(x[0] for x in files.values()))
        self.assertIn('User=afs-api', api)
        self.assertIn('User=afs-caddy', web)

    def test_proxy_no_implicit_trust(self):
        files = installer.rendered(self.config('--mode', 'proxy'))
        caddy = files[installer.ETC / 'Caddyfile'][0]
        self.assertIn('http://:8000 {', caddy)
        self.assertNotIn('\tbind ', caddy)
        self.assertIn('auto_https off', caddy)
        self.assertNotIn('trusted_proxies', caddy)
        web = files[installer.UNITS / installer.WEB_UNIT][0]
        self.assertIn('CapabilityBoundingSet=\n', web)
        self.assertIn('AmbientCapabilities=\n', web)
        self.assertNotIn('CAP_NET_BIND_SERVICE', web)

    def test_proxy_explicit_cidrs(self):
        c = self.config('--mode', 'proxy', '--listen', '127.0.0.1:8000',
                        '--trusted-proxy', '127.0.0.1/32', '--trusted-proxy', '2001:db8::/64')
        text = installer.rendered(c)[installer.ETC / 'Caddyfile'][0]
        self.assertIn('trusted_proxies static 127.0.0.1/32 2001:db8::/64', text)
        self.assertIn('trusted_proxies_strict', text)
        self.assertNotIn('private_ranges', text)
        self.assertIn('http://:8000 {\n\tbind 127.0.0.1\n', text)

    def test_bad_origins(self):
        for url in ('http://files.example.com', 'https://x/y', 'https://u:p@x', 'https://x/?x=1',
                    'https://x/#secret', 'https://x\nheader', 'https://x;evil.com', 'https://a..b',
                    'https://files.example.com/?', 'https://files.example.com/#', 'https://[::1]', 'https://127.0.0.1', 'https://files.example.com:8000', 'https://x/"'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                installer.configuration(self.args('--base-url', url))

    def test_bad_namespace(self):
        for ns in ('../x', 'a b', 'x\nEVIL=1', 'x;echo', 'x' * 65, 'é'):
            with self.subTest(ns=ns), self.assertRaises(ValueError):
                self.config('--namespace', ns)

    def test_direct_trust_and_listen_forbidden(self):
        for args in (('--trusted-proxy', '127.0.0.1/32'), ('--listen', ':8000')):
            with self.assertRaises(ValueError):
                self.config(*args)

    def test_bad_proxy(self):
        for args in (('--trusted-proxy', 'private_ranges'), ('--trusted-proxy', '0.0.0.0/0'),
                     ('--trusted-proxy', '::/0'), ('--trusted-proxy', '127.0.0.1/24'),
                     ('--listen', ':80'), ('--listen', ':65536'), ('--listen', ':8000\nheader'),
                     ('--listen', 'evil.com:8000')):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.config('--mode', 'proxy', *args)

    def test_render_new_private_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'render'
            installer.write_render(path, installer.rendered(self.config()))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            env = path / str(installer.ETC / 'environment').lstrip('/')
            self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                installer.write_render(path, installer.rendered(self.config()))

    def test_render_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'mine').write_text('retain')
            with self.assertRaises(ValueError):
                installer.write_render(root, installer.rendered(self.config()))
            self.assertEqual((root / 'mine').read_text(), 'retain')

    def test_fresh_refuses_every_unmanaged_path(self):
        paths = [*installer.DIRECTORIES, installer.API_BINARY, installer.WEB_BINARY,
                 installer.UNITS / installer.API_UNIT, installer.UNITS / installer.WEB_UNIT, installer.UNITS / installer.HEALTH_UNIT,
                 installer.UNITS / installer.HEALTH_TIMER, installer.HEALTH_BINARY,
                 installer.BIN / 'agent-fileserver', installer.BIN / 'agent-fileserver-token',
                 Path('/run/agent-fileserver-api')]
        for p in paths:
            with self.subTest(path=p), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = installer.host_path(root, p)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('unmanaged')
                with self.assertRaises(ValueError):
                    installer.preflight(self.args(), root)
                self.assertEqual(target.read_text(), 'unmanaged')

    def test_fresh_no_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertIsNone(installer.preflight(self.args(), root))
            self.assertEqual(list(root.iterdir()), [])

    def test_upgrade_requires_manifest(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            installer.preflight(self.args('--upgrade'), Path(tmp))

    def test_upgrade_preserves_uninventoried_data_and_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            secret = installer.host_path(root, installer.DATA / 'credentials/tokens.json')
            secret.parent.mkdir()
            secret.write_text('fixture secret remains private')
            self.assertIsNotNone(installer.preflight(self.args('--upgrade'), root))
            self.assertEqual(secret.read_text(), 'fixture secret remains private')

    def test_upgrade_refuses_edited_config_binary_and_mode(self):
        for name in (installer.ETC / 'Caddyfile', installer.API_BINARY, installer.ETC / 'environment'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root)
                installer.host_path(root, name).write_text('operator edit')
                with self.assertRaises(ValueError):
                    installer.preflight(self.args('--upgrade'), root)
                self.assertEqual(installer.host_path(root, name).read_text(), 'operator edit')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            installer.host_path(root, installer.ETC / 'environment').chmod(0o644)
            with self.assertRaises(ValueError):
                installer.preflight(self.args('--upgrade'), root)

    def test_upgrade_refuses_config_change(self):
        old = self.config()
        with self.assertRaises(ValueError):
            installer.configuration(self.args('--upgrade', '--namespace', 'other'), old)
        self.assertEqual(installer.configuration(self.args('--upgrade'), old), old)

    def test_symlink_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'etc').symlink_to('/etc')
            with self.assertRaises(ValueError):
                installer.preflight(self.args(), root)

    def test_upgrade_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            path = installer.host_path(root, installer.API_BINARY)
            path.unlink()
            path.symlink_to('/bin/true')
            with self.assertRaises(ValueError):
                installer.preflight(self.args('--upgrade'), root)

    def test_upgrade_inventory_cannot_target_unmanaged_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = self.fixture(root)
            marker['files']['/etc/shadow'] = {'sha256': '0' * 64, 'mode': 0o600}
            installer.host_path(root, installer.MANIFEST).write_text(json.dumps(marker))
            with self.assertRaises(ValueError):
                installer.preflight(self.args('--upgrade'), root)

    def test_upgrade_reuses_managed_caddy_not_unrelated_path_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            web = Path('/bin/true')
            with mock.patch.object(installer, 'WEB_BINARY', web):
                api, selected = installer.dependencies(self.args('--upgrade', '--binary', '/bin/true'), directory)
            self.assertEqual(selected, web)

    def test_noexec_download_error_explains_tmpdir(self):
        with mock.patch.object(installer.subprocess, 'run', side_effect=PermissionError('fixture noexec')):
            with self.assertRaisesRegex(ValueError, 'set TMPDIR'):
                installer.run(['/tmp/fixture-go', 'version'])

    def test_missing_brotli_fails_before_install(self):
        actual = shutil.which
        with mock.patch.object(installer.shutil, 'which', side_effect=lambda name: None if name == 'brotli' else actual(name)):
            with self.assertRaisesRegex(ValueError, 'missing prerequisites: brotli'):
                installer.prerequisites()

    def test_atomic_write_preserves_previous_file_on_rename_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'managed'
            path.write_bytes(b'old')
            path.chmod(0o600)
            with mock.patch.object(installer.os, 'replace', side_effect=OSError('fixture failure')):
                with self.assertRaises(OSError):
                    installer.atomic_write(path, b'new', 0o644)
            self.assertEqual(path.read_bytes(), b'old')
            self.assertEqual(list(Path(tmp).iterdir()), [path])
            installer.atomic_write(path, b'new', 0o644)
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_checksum_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'download'
            path.write_bytes(b'fixture')
            checksum(path, hashlib.sha256(b'fixture').hexdigest())
            checksum(path, hashlib.sha512(b'fixture').hexdigest())
            with self.assertRaises(ValueError):
                checksum(path, '0' * 64)
            with self.assertRaises(ValueError):
                checksum(path, 'not a checksum')

    def test_health_default_optional_and_sandbox(self):
        self.assertTrue(self.config()['healthcheck'])
        self.assertFalse(self.config('--no-healthcheck')['healthcheck'])
        files = installer.rendered(self.config())
        health = files[installer.UNITS / installer.HEALTH_UNIT][0]
        self.assertIn('SupplementaryGroups=afs-caddy', health)
        self.assertIn('CapabilityBoundingSet=\n', health)
        self.assertIn('ProtectHome=true', health)
        self.assertIn('TimeoutStartSec=60s', health)
        timer = files[installer.UNITS / installer.HEALTH_TIMER][0]
        self.assertIn('OnUnitActiveSec=60s', timer)
        self.assertIn('WantedBy=timers.target', timer)

    def test_health_probe_only_restarts_active_unhealthy_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            log = directory / 'calls'
            systemctl = directory / 'systemctl'
            systemctl.write_text('#!/bin/sh\nif [ "$1" = is-active ]; then [ "$ACTIVE" = yes ]; else echo "$*" >>"$CALLS"; fi\n')
            curl = directory / 'curl'
            curl.write_text('#!/bin/sh\ncase "$*" in *--unix-socket*) exit "$API_RC";; *) printf %s "$HTTP_STATUS"; exit 0;; esac\n')
            for p in (systemctl, curl):
                p.chmod(0o755)
            source = (REPO / 'deploy/agent-fileserver-healthcheck').read_text()
            source = source.replace('/usr/bin/systemctl', '/bin/sh ' + str(systemctl)).replace('/usr/bin/curl', '/bin/sh ' + str(curl))
            script = directory / 'healthcheck'
            script.write_text(source)
            script.chmod(0o755)
            for active, rc, status, mode, expected in (
                    ('no', '1', '500', 'proxy', []),
                    ('yes', '0', '404', 'proxy', []),
                    ('yes', '0', '308', 'direct', []),
                    ('yes', '0', '404', 'direct', []),
                    ('yes', '1', '404', 'proxy', ['agent-fileserver-api.service']),
                    ('yes', '0', '500', 'proxy', ['agent-fileserver.service']),
                    ('yes', '1', '000', 'direct', ['agent-fileserver-api.service', 'agent-fileserver.service'])):
                with self.subTest(active=active, rc=rc, status=status, mode=mode):
                    if log.exists():
                        log.unlink()
                    env = dict(os.environ, CALLS=str(log), ACTIVE=active, API_RC=rc, HTTP_STATUS=status,
                               FSERVER_MODE=mode, FSERVER_BASE_URL='https://files.example.com', FSERVER_LISTEN=':8000')
                    subprocess.run(['/bin/sh', str(script)], check=True, env=env, capture_output=True)
                    calls = log.read_text().splitlines() if log.exists() else []
                    self.assertEqual(calls, ['try-restart ' + unit for unit in expected])

    def test_validation_uses_shell_without_executing_temp_health_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            files = installer.rendered(self.config())
            installer.write_render(directory, files)
            helper = directory / str(installer.HEALTH_BINARY).lstrip('/')
            # Equivalent executable-availability constraint to a noexec mount.
            helper.chmod(0o600)
            commands = []
            def inspect(args, **kwargs):
                commands.append([str(x) for x in args])
                if args[0] == 'systemd-analyze':
                    unit = Path(args[-2]).read_text()
                    self.assertIn('ExecStart=/bin/sh ' + str(helper), unit)
                    self.assertIn('SupplementaryGroups=afs-caddy', unit)
                    self.assertIn('ProtectHome=true', unit)
                    self.assertIn('CapabilityBoundingSet=\n', unit)
            with mock.patch.object(installer, 'run', side_effect=inspect):
                installer.validate(directory, Path('/bin/true'), Path('/bin/true'))
            self.assertIn(['/bin/sh', '-n', str(helper)], commands)
            self.assertNotIn([str(helper)], commands)
            self.assertIn('ExecStart=/usr/local/libexec/agent-fileserver-healthcheck',
                          files[installer.UNITS / installer.HEALTH_UNIT][0])

    @unittest.skipUnless(shutil.which('caddy') and shutil.which('systemd-analyze'), 'requires Caddy and systemd-analyze')
    def test_caddy_and_systemd_validate_direct_and_proxy(self):
        for args in ((), ('--mode', 'proxy'), ('--mode', 'proxy', '--trusted-proxy', '127.0.0.1/32')):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                installer.write_render(directory, installer.rendered(self.config(*args)))
                # API executable stub for unit syntax checking only; never activates.
                installer.validate(directory, Path('/bin/true'), Path(shutil.which('caddy')))


if __name__ == '__main__':
    unittest.main()
