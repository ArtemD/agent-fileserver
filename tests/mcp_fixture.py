"""Shared installed-server fixture: owner-CLI keys plus MCP tool calls.

MCP is the only management interface, so tests create releases exactly the way
agents do. Python stdlib and curl only. The fixture key lives in a private 0600
header file, never in command arguments, output or exceptions. Each fixture
deletes only the releases it created and revokes only its own one-day key.

Knobs: FSERVER_TEST_ADMIN (shlex-split owner administration command; defaults
to /usr/local/bin/agent-fileserver as root, otherwise sudo plus that path).
"""

import base64
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tarfile
import tempfile

ADMIN = shlex.split(os.environ.get(
    "FSERVER_TEST_ADMIN", "/usr/local/bin/agent-fileserver"
    if os.geteuid() == 0 else "sudo /usr/local/bin/agent-fileserver"))
KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{22}\Z")


class FixtureError(Exception):
    """Messages are constant stages, never response bodies or credentials."""


def one_root_tar(source):
    """Pack a file or directory as a one-root tar, keeping empty directories."""
    source = Path(source)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        paths = [source] + (sorted(source.rglob("*")) if source.is_dir() else [])
        for path in paths:
            name = source.name if path == source else source.name + "/" + path.relative_to(source).as_posix()
            info = tarfile.TarInfo(name)
            if path.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            else:
                data = path.read_bytes()
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class MCPFixture:
    def __init__(self, base, resolve=None, prefix="fixture"):
        self.base, self.resolve = base.rstrip("/"), resolve
        self.label = prefix + "-" + secrets.token_hex(8)
        self.releases = []
        self.work = tempfile.TemporaryDirectory(prefix="agent-fileserver-fixture-")
        os.chmod(self.work.name, 0o700)
        result = subprocess.run([*ADMIN, "token", "create", "--label", self.label, "--days", "1"],
                                capture_output=True, text=True, timeout=30)
        self.key = result.stdout.strip()
        if result.returncode != 0 or not KEY.fullmatch(self.key):
            raise FixtureError("fixture key creation failed")
        self.headers = Path(self.work.name) / "headers"
        fd = os.open(self.headers, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write("Authorization: Bearer " + self.key + "\n"
                      "Content-Type: application/json\n"
                      "Accept: application/json, text/event-stream\n"
                      "MCP-Protocol-Version: 2025-06-18\n")

    def tool(self, name, arguments):
        body = Path(self.work.name) / ("body-" + secrets.token_hex(6))
        body.write_text(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": name, "arguments": arguments}}))
        cmd = ["curl", "-q", "--silent", "--show-error", "--max-time", "190",
               "--header", "@" + str(self.headers), "--data-binary", "@" + str(body),
               "--write-out", "\n%{http_code}"]
        if self.resolve:
            cmd += ["--resolve", self.resolve]
        result = subprocess.run([*cmd, self.base + "/mcp"], capture_output=True, text=True, timeout=200)
        body.unlink()
        if result.returncode != 0:
            raise FixtureError("MCP transport failed: " + name)
        text, _, status = result.stdout.rpartition("\n")
        try:
            content = json.loads(text)["result"]
            if status != "200" or content.get("isError"):
                raise FixtureError("MCP tool failed: " + name)
            return json.loads(content["content"][0]["text"])
        except (ValueError, KeyError, IndexError, TypeError):
            raise FixtureError("MCP response invalid: " + name) from None

    def publish(self, source, spa=False):
        view = self.tool("publish_archive", {
            "label": self.label, "spa": spa, "idempotency_key": secrets.token_urlsafe(24),
            "archive_base64": base64.b64encode(one_root_tar(source)).decode()})
        if not TOKEN.fullmatch(view.get("token", "")):
            raise FixtureError("publish returned invalid release metadata")
        self.releases.append(view["token"])
        return view

    def delete(self, token):
        self.tool("delete_release", {"token": token})
        self.releases.remove(token)

    def close(self):
        failed = False
        try:
            for token in list(self.releases):
                try:
                    self.delete(token)
                except FixtureError:
                    failed = True
        finally:
            revoked = subprocess.run([*ADMIN, "token", "revoke", self.label],
                                     capture_output=True, timeout=30)
            self.work.cleanup()
        if failed or revoked.returncode != 0:
            raise FixtureError("fixture cleanup failed")
