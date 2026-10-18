#!/usr/bin/env python3
"""Official, checksum-verified native build/runtime dependency downloads.

Versions intentionally pinned. Update only after checking official release metadata.
No remote installer scripts, package repository changes, or host toolchain replacement.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile

GO_VERSION = '1.27.2'
CADDY_VERSION = '2.11.7'


def fetch(url, path):
    subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location',
                    '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                    '--retry', '3', '--connect-timeout', '20', '--max-time', '600',
                    '--output', str(path), url], check=True)


def checksum(path, expected):
    if not re.fullmatch(r'(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128})', expected):
        raise ValueError('invalid official SHA-256/SHA-512 metadata')
    with open(path, 'rb') as f:
        h = hashlib.sha256() if len(expected) == 64 else hashlib.sha512()
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
        actual = h.hexdigest()
    if actual.lower() != expected.lower():
        raise ValueError(f'official checksum mismatch: {path.name}')


def architecture():
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or arch is None:
        raise ValueError('supported platform: native Linux amd64 or arm64')
    return arch


def caddy(directory):
    arch = architecture()
    name = f'caddy_{CADDY_VERSION}_linux_{arch}.tar.gz'
    base = f'https://github.com/caddyserver/caddy/releases/download/v{CADDY_VERSION}/'
    sums = directory / 'caddy-checksums.txt'
    archive = directory / name
    fetch(base + f'caddy_{CADDY_VERSION}_checksums.txt', sums)
    expected = None
    for line in sums.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip('*') == name:
            expected = fields[0]
    if not expected:
        raise ValueError('Caddy release checksum not found')
    fetch(base + name, archive)
    checksum(archive, expected)
    output = directory / 'caddy'
    with tarfile.open(archive) as tar:
        member = tar.getmember('caddy')
        if not member.isfile():
            raise ValueError('Caddy archive binary is not a regular file')
        with tar.extractfile(member) as source, output.open('xb') as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    output.chmod(0o755)
    return output


def go(directory):
    arch = architecture()
    # Current release metadata is small; fall back to history when this pin ages.
    metadata = directory / 'go-releases.json'
    name = f'go{GO_VERSION}.linux-{arch}.tar.gz'
    files = []
    for url in ('https://go.dev/dl/?mode=json', 'https://go.dev/dl/?mode=json&include=all'):
        fetch(url, metadata)
        files = [f for r in json.loads(metadata.read_text()) if r['version'] == 'go' + GO_VERSION
                 for f in r['files'] if f['filename'] == name]
        if files:
            break
    if len(files) != 1:
        raise ValueError('pinned Go version not present in official metadata')
    archive = directory / name
    fetch('https://go.dev/dl/' + name, archive)
    checksum(archive, files[0]['sha256'])
    # Validate all archive names/types first, then extract only regular files/dirs.
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != 'go' or '..' in parts or Path(member.name).is_absolute():
                raise ValueError('unsafe Go archive path')
            if not (member.isfile() or member.isdir()):
                raise ValueError('unexpected Go archive entry type')
        for member in tar.getmembers():
            target = directory / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open('xb') as out:
                    while chunk := source.read(1024 * 1024):
                        out.write(chunk)
                target.chmod(member.mode & 0o755)
    return directory / 'go/bin/go'
