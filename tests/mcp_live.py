#!/usr/bin/env python3
"""Opt-in installed-server MCP acceptance; Python stdlib and curl only.

Run: python3 tests/mcp_live.py
Knobs: FSERVER_TEST_BASE (default http://localhost:8000),
FSERVER_TEST_RESOLVE (curl --resolve, with normal TLS verification), and
FSERVER_TEST_ADMIN (shlex-split owner key-administration command; defaults to
`docker compose run --rm -T admin`, run from the repository root).

Creates its own one-day fixture credentials and synthetic releases, then deletes
only those releases and revokes only those credentials. Never reads the registry.
Credentials/passwords are private header files, not command arguments. Failures
and subprocess output are deliberately redacted. No installed service changes.
Upload tickets (begin_upload, then PUT /_upload) are exercised with small files;
the ticket travels only in a private header file, never in argv.
Set FSERVER_TEST_LARGE=1 for an additional exact-100-MiB decoded archive check
and a 256 MiB single-file upload/download round trip.
"""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from urllib.parse import urlsplit
import zipfile
import zlib


BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000").rstrip("/")
RESOLVE = os.environ.get("FSERVER_TEST_RESOLVE")
CLI = shlex.split(os.environ.get("FSERVER_TEST_ADMIN", "docker compose run --rm -T admin"))
TOKEN = re.compile(r"[A-Za-z0-9_-]{22}\Z")
KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
HTML = b"<!doctype html><title>MCP fixture</title><h1>Published through MCP</h1>"
CSS = b"body { color: #123456; background: white; }\n"


def png_chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))


PNG = (b"\x89PNG\r\n\x1a\n"
       + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
       + png_chunk(b"IDAT", zlib.compress(b"\x00\x12\x34\x56"))
       + png_chunk(b"IEND", b""))


class LiveFailure(Exception):
    """Messages are constant diagnostic stages, never response/body data."""


def check(condition, message):
    if not condition:
        raise LiveFailure(message)


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def sha256(data):
    return hashlib.sha256(data).digest()


class SafeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        if isinstance(err[1], LiveFailure):
            return "Live acceptance check failed: " + str(err[1])
        return "Unexpected acceptance failure (details redacted to protect credentials)."


class SafeRunner(unittest.TextTestRunner):
    resultclass = SafeResult


class MCPLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="agent-fileserver-mcp-live-")
        cls.work = Path(cls.tmp.name)
        cls.work.chmod(0o700)
        cls.tag = "mcp-live-" + secrets.token_hex(10)
        cls.labels = set()
        cls.releases = set()
        cls.release_labels = set()
        cls.seq = 0
        cls.key = None
        cls.addClassCleanup(cls.cleanup)
        parsed = urlsplit(BASE)
        check(parsed.scheme in ("http", "https") and parsed.hostname
              and parsed.username is None and parsed.password is None
              and not parsed.query and not parsed.fragment,
              "FSERVER_TEST_BASE must be an HTTP(S) origin without credentials/query")
        check(bool(CLI) and shutil.which("curl"), "local CLI and curl are required")
        cls.key = cls.create_key(cls.tag)

    @classmethod
    def command(cls, args, stage):
        result = subprocess.run([*CLI, *args], capture_output=True, timeout=30)
        check(result.returncode == 0, stage)
        return result.stdout

    @classmethod
    def create_key(cls, label):
        # Track before creation, so setup failure still attempts revocation.
        cls.labels.add(label)
        raw = cls.command(["token", "create", "--label", label, "--days", "1"],
                          "fixture credential creation failed").decode().strip()
        if raw.startswith("{"):
            try:
                obj = json.loads(raw)
                candidates = [obj.get(field) for field in
                              ("key", "token", "api_key", "bearer")]
                candidates = [value for value in candidates
                              if isinstance(value, str) and KEY.fullmatch(value)]
                check(len(candidates) == 1, "unsupported CLI credential JSON format")
                raw = candidates[0]
            except (ValueError, AttributeError):
                raise LiveFailure("unsupported CLI credential output") from None
        check(KEY.fullmatch(raw), "unsupported CLI credential output")
        return raw

    @classmethod
    def cleanup(cls):
        failed = False
        try:
            if cls.key:
                # Recover only OUR exact labels after any ambiguous tool result.
                try:
                    items = cls.tool("list_releases", {})
                    if isinstance(items, list):
                        for item in items:
                            if (isinstance(item, dict)
                                    and item.get("label") in cls.release_labels
                                    and TOKEN.fullmatch(item.get("token", ""))):
                                cls.releases.add(item["token"])
                except Exception:
                    failed = True
                for token in sorted(cls.releases):
                    try:
                        # A release the test already deleted is fine; anything
                        # else that still exists must be deleted successfully.
                        if cls.request("/" + token + "/", anonymous=True)[0] == 404:
                            try:
                                cls.tool("release_info", {"token": token})
                            except LiveFailure:
                                continue
                        cls.tool("delete_release", {"token": token})
                    except Exception:
                        failed = True
        finally:
            for label in sorted(cls.labels):
                try:
                    cls.command(["token", "revoke", label],
                                "fixture credential cleanup failed")
                except Exception:
                    failed = True
            cls.tmp.cleanup()
        check(not failed, "fixture-only release/credential cleanup failed")

    @classmethod
    def request(cls, path, method="GET", *, body=None, key=None,
                anonymous=False, password=None, headers=None, max_bytes=4 << 20,
                as_file=False, key_header="authorization", upload=None, max_time=190):
        cls.seq += 1
        stem = cls.work / ("request-" + str(cls.seq))
        hfile = stem.with_suffix(".headers")
        response_headers = stem.with_suffix(".response-headers")
        response_body = stem.with_suffix(".response")
        lines = ["User-Agent: agent-fileserver-mcp-live", "Accept-Encoding: identity"]
        if password is not None:
            basic = base64.b64encode(("viewer:" + password).encode()).decode()
            lines.append("Authorization: Basic " + basic)
        elif not anonymous and key_header == "x-auth-token":
            lines.append("X-Auth-Token: " + (key or cls.key))
        elif not anonymous:
            lines.append("Authorization: Bearer " + (key or cls.key))
        for name, value in (headers or {}).items():
            lines.append(name + ": " + value)
        private_write(hfile, ("\n".join(lines) + "\n").encode())
        private_write(response_headers, b"")
        private_write(response_body, b"")
        args = ["curl", "-q", "--silent", "--show-error", "--path-as-is",
                "--max-time", str(max_time), "--max-filesize", str(max_bytes),
                "--request", method, "--header", "@" + str(hfile),
                "--dump-header", str(response_headers),
                "--output", str(response_body), "--write-out", "%{http_code}"]
        if RESOLVE:
            args += ["--resolve", RESOLVE]
        if body is not None:
            if not isinstance(body, Path):
                bfile = stem.with_suffix(".body")
                private_write(bfile, body)
                body = bfile
            args += ["--data-binary", "@" + str(body)]
        if upload is not None:
            # Streamed from disk (--data-binary would buffer the whole file).
            args += ["--upload-file", str(upload)]
        result = subprocess.run(args + [BASE + path], capture_output=True,
                                timeout=max_time + 10)
        check(result.returncode == 0, "curl transport failed (output redacted)")
        check(result.stdout.strip().isdigit(), "invalid curl status")
        check(response_body.stat().st_size <= max_bytes, "response exceeds test bound")
        parsed = {}
        for line in response_headers.read_text(errors="replace").splitlines():
            if line.startswith("HTTP/"):
                parsed = {}  # only the final response; 1xx blocks (Expect: 100-continue) precede it
            elif ":" in line:
                name, value = line.split(":", 1)
                # Repeated fields combine (RFC 9110 5.3), so equality checks catch duplicates.
                name = name.lower()
                parsed[name] = parsed[name] + ", " + value.strip() if name in parsed else value.strip()
        return (int(result.stdout.strip()), parsed,
                response_body if as_file else response_body.read_bytes())

    @classmethod
    def rpc(cls, method, params=None, *, key=None, notification=False, body_file=None):
        if body_file is None:
            message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
            if not notification:
                message["id"] = secrets.randbelow(1 << 30) + 1
            body_file = json.dumps(message, separators=(",", ":")).encode()
        status, headers, body = cls.request(
            "/mcp", "POST", body=body_file, key=key,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream",
                     "MCP-Protocol-Version": "2025-06-18"})
        if notification:
            check(status in (200, 202, 204), "MCP initialized notification failed")
            return None
        check(status == 200, "MCP request failed")
        check("mcp-session-id" not in headers, "server unexpectedly created a session")
        check(headers.get("cache-control") in ("no-store", "no-store, no-transform"),
              "MCP response is storable or has duplicate Cache-Control")
        check("access-control-allow-origin" not in headers, "unexpected MCP CORS")
        try:
            response = json.loads(body)
        except ValueError:
            raise LiveFailure("MCP returned invalid JSON") from None
        check(isinstance(response, dict) and not response.get("error")
              and "result" in response, "MCP JSON-RPC error (details redacted)")
        return response["result"]

    @classmethod
    def tool(cls, name, arguments, *, body_file=None):
        result = cls.rpc("tools/call", {"name": name, "arguments": arguments},
                         body_file=body_file)
        check(isinstance(result, dict) and not result.get("isError"),
              "MCP tool failed: " + name)
        contents = result.get("content", [])
        check(len(contents) == 1 and contents[0].get("type") == "text",
              "MCP tool result shape mismatch")
        try:
            return json.loads(contents[0]["text"])
        except (ValueError, KeyError, TypeError):
            raise LiveFailure("MCP tool returned invalid JSON text") from None

    @classmethod
    def publish(cls, name="publish_files", *, password=None, args=None):
        if args is None:
            label = cls.tag + "-" + secrets.token_hex(6)
            cls.release_labels.add(label)
            args = {"label": label, "idempotency_key": secrets.token_urlsafe(24),
                    "files": [{"path": "index.html", "text": HTML.decode()},
                              {"path": "assets/style.css", "text": CSS.decode()}]}
            if password is not None:
                args["password"] = password
        view = cls.tool(name, args)
        check(isinstance(view, dict) and TOKEN.fullmatch(view.get("token", "")),
              "published release metadata invalid")
        cls.releases.add(view["token"])
        return view

    @classmethod
    def public_bytes(cls, token, relative, expected, *, password=None):
        status, _, data = cls.request("/" + token + "/" + relative,
                                      anonymous=True, password=password)
        check(status == 200 and sha256(data) == sha256(expected),
              "published asset status/content hash mismatch")

    def test_01_initialize_and_initialized(self):
        result = self.rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "agent-fileserver-live-test", "version": "1"}})
        check(result.get("protocolVersion") == "2025-06-18"
              and result.get("serverInfo") and "tools" in result.get("capabilities", {}),
              "MCP initialize negotiation failed")
        self.rpc("notifications/initialized", notification=True)

    def test_02_tools_and_identity(self):
        result = self.rpc("tools/list")
        tools = {tool["name"]: tool for tool in result.get("tools", [])}
        expected = {"server_info", "list_releases", "release_info", "publish_files",
                    "publish_archive", "download_release", "delete_release",
                    "set_password", "reset_password", "remove_password", "begin_upload"}
        check(expected <= tools.keys(), "required MCP tools missing")
        for name in ("publish_files", "publish_archive", "remove_password", "begin_upload"):
            check(tools[name].get("annotations", {}).get("openWorldHint") is True,
                  "public side-effect annotation missing")
        me = self.tool("server_info", {})
        check(me.get("agent") == self.tag and me.get("namespace"),
              "authenticated MCP identity mismatch")
        upload = me.get("upload")
        check(isinstance(upload, dict)
              and all(type(upload.get(field)) is int for field in (
                  "max_bytes", "max_extract_bytes", "max_entries",
                  "ticket_seconds", "max_pending_tickets")),
              "server_info upload limits missing or malformed")

    def test_03_publish_files_and_anonymous_assets(self):
        view = self.publish()
        check(not view.get("protected") and view.get("files") == 2,
              "raw-file website metadata mismatch")
        self.public_bytes(view["token"], "index.html", HTML)
        self.public_bytes(view["token"], "assets/style.css", CSS)

    def test_04_publish_flat_zip_html_css_binary(self):
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in (("index.html", HTML), ("style.css", CSS),
                                  ("pixel.png", PNG)):
                archive.writestr(name, content)
        label = self.tag + "-zip"
        self.release_labels.add(label)
        view = self.publish("publish_archive", args={
            "label": label, "idempotency_key": secrets.token_urlsafe(24),
            "archive_base64": base64.b64encode(zipped.getvalue()).decode()})
        check(view.get("files") == 3, "ZIP website entry count mismatch")
        for name, content in (("index.html", HTML), ("style.css", CSS), ("pixel.png", PNG)):
            self.public_bytes(view["token"], name, content)

    def test_05_exact_idempotent_retry(self):
        label = self.tag + "-idempotent"
        self.release_labels.add(label)
        args = {"label": label, "idempotency_key": secrets.token_urlsafe(24),
                "files": [{"path": "document.txt", "text": "idempotent fixture\n"}]}
        first = self.publish(args=args)
        second = self.publish(args=args)
        check(first["token"] == second["token"], "publish retry created another release")

    def test_06_list_and_release_info(self):
        view = self.publish()
        info = self.tool("release_info", {"token": view["token"]})
        items = self.tool("list_releases", {})
        check(info.get("token") == view["token"] and isinstance(items, list)
              and any(item.get("token") == view["token"] for item in items),
              "MCP list/info mismatch")

    def test_07_download_base64_original_hash(self):
        label = self.tag + "-download"
        self.release_labels.add(label)
        view = self.publish(args={
            "label": label, "idempotency_key": secrets.token_urlsafe(24),
            "files": [{"path": "pixel.png",
                       "content_base64": base64.b64encode(PNG).decode()}]})
        result = self.tool("download_release", {"token": view["token"]})
        check(result.get("inline") is True, "small MCP download was not inline")
        try:
            decoded = base64.b64decode(result["content_base64"], validate=True)
        except (ValueError, KeyError, TypeError):
            raise LiveFailure("inline download base64 invalid") from None
        check(sha256(decoded) == sha256(PNG), "inline download hash mismatch")

    def test_08_password_set_reset_remove(self):
        view = self.publish()
        token = view["token"]
        password = secrets.token_urlsafe(24)
        self.tool("set_password", {"token": token, "password": password})
        check(self.request("/" + token + "/assets/style.css", anonymous=True)[0] == 401,
              "protected assets unexpectedly public")
        self.public_bytes(token, "assets/style.css", CSS, password=password)
        for query in ("?", "?fbclid=x&utm_source=y", "?p=..%2F..%2Findex.html"):
            check(self.request("/" + token + "/index.html" + query, anonymous=True)[0] == 401,
                  "query string bypassed or broke visitor authentication")
            self.public_bytes(token, "index.html" + query, HTML, password=password)
        reset = self.tool("reset_password", {"token": token})
        replacement = reset.get("password")
        check(isinstance(replacement, str) and 8 <= len(replacement.encode()) <= 72,
              "reset did not return a usable visitor password")
        self.public_bytes(token, "index.html", HTML, password=replacement)
        check(self.request("/" + token + "/index.html", anonymous=True,
                           password=password)[0] == 401,
              "old visitor password survived reset")
        self.tool("remove_password", {"token": token})
        self.public_bytes(token, "assets/style.css", CSS)

    def test_09_delete_fixture(self):
        view = self.publish()
        token = view["token"]
        result = self.tool("delete_release", {"token": token})
        check(result.get("ok") is True
              and self.request("/" + token + "/index.html", anonymous=True)[0] == 404,
              "deleted fixture remains public")
        self.releases.discard(token)

    def test_10_revoke_previously_initialized_credential(self):
        label = self.tag + "-revocation"
        key = self.create_key(label)
        self.rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "revocation-fixture", "version": "1"}}, key=key)
        self.rpc("notifications/initialized", notification=True, key=key)
        self.rpc("tools/list", key=key)
        self.command(["token", "revoke", label], "fixture credential revocation failed")
        message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                              "params": {}}).encode()
        status, _, body = self.request("/mcp", "POST", body=message, key=key, headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18"})
        if status == 429:
            # Other acceptance suites may have filled the shared-IP failed-key
            # bucket. This exact API error still proves authentication rejected
            # the revoked key (not a publisher/MCP admission limit).
            try:
                auth_limited = json.loads(body).get("error") == "too many authentication failures"
            except (ValueError, AttributeError):
                auth_limited = False
            check(auth_limited, "revocation check hit a non-authentication rate limit")
            check(self.tool("server_info", {}).get("agent") == self.tag,
                  "a failed credential locked out a valid credential")
        else:
            check(status == 401, "revoked credential was not rejected by authentication")
        self.__class__.revocation_status = status

    def test_12_x_auth_token_header(self):
        # Claude's connector dialog sends static keys as a custom header.
        message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "server_info", "arguments": {}}}).encode()
        status, _, body = self.request("/mcp", "POST", body=message, key_header="x-auth-token",
                                       headers={"Content-Type": "application/json",
                                                "Accept": "application/json, text/event-stream",
                                                "MCP-Protocol-Version": "2025-06-18"})
        check(status == 200 and self.tag in body.decode(errors="replace"),
              "X-Auth-Token authentication failed")

    def test_13_mcp_is_the_only_management_interface(self):
        for path in ("/_api/v1/me", "/_api/v1/releases", "/_internal/health",
                     "/_internal/authorize"):
            for method in ("GET", "POST"):
                status, _, _ = self.request(path, method, body=b"{}" if method == "POST" else None)
                check(status in (404, 405), "non-MCP management route is reachable: " + path)

    @classmethod
    def begin_upload(cls, size, digest, *, filename=None, label=None, idempotency_key=None):
        label = label or cls.tag + "-upload-" + secrets.token_hex(4)
        cls.release_labels.add(label)
        args = {"size": size, "sha256": digest, "label": label,
                "idempotency_key": idempotency_key or secrets.token_urlsafe(24)}
        if filename is not None:
            args["filename"] = filename
        ticket = cls.tool("begin_upload", args)
        check(isinstance(ticket, dict), "begin_upload result shape mismatch")
        return ticket

    @staticmethod
    def ticket_secret(ticket):
        headers = ticket.get("headers")
        auth = headers.get("Authorization") if isinstance(headers, dict) else None
        check(isinstance(auth, str) and auth.startswith("Bearer upl_"),
              "upload ticket header missing or malformed")
        return auth[len("Bearer "):]

    @classmethod
    def put_upload(cls, ticket, path, *, key=None, anonymous=False, **kwargs):
        """PUT a file to /_upload with the ticket (or another credential) in a private header file."""
        if key is None and not anonymous:
            key = cls.ticket_secret(ticket)
        return cls.request("/_upload", "PUT", upload=path, key=key, anonymous=anonymous, **kwargs)

    @classmethod
    def uploaded_release(cls, status, body, stage):
        check(status == 201, stage + ": upload not accepted")
        try:
            view = json.loads(body)
        except ValueError:
            raise LiveFailure(stage + ": upload returned invalid JSON") from None
        check(isinstance(view, dict) and TOKEN.fullmatch(view.get("token", "")),
              stage + ": uploaded release metadata invalid")
        cls.releases.add(view["token"])
        return view

    @staticmethod
    def auth_refused(result):
        """401, or the shared per-IP failed-credential limit other suites may have filled (see test_10)."""
        status, _, body = result
        if status == 429:
            try:
                return json.loads(body).get("error") == "too many authentication failures"
            except (ValueError, AttributeError):
                return False
        return status == 401

    def write_fixture(self, name, data):
        path = self.work / name
        private_write(path, data)
        return path

    def test_14_archive_upload_ticket_single_use_and_idempotent(self):
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in (("index.html", HTML), ("style.css", CSS),
                                  ("pixel.png", PNG)):
                archive.writestr(name, content)
        data = zipped.getvalue()
        path = self.write_fixture("upload-site.zip", data)
        label = self.tag + "-upload-zip"
        idem = secrets.token_urlsafe(24)
        digest = hashlib.sha256(data).hexdigest()
        ticket = self.begin_upload(len(data), digest, label=label, idempotency_key=idem)
        check(ticket.get("method") == "PUT" and isinstance(ticket.get("upload_url"), str)
              and ticket["upload_url"].endswith("/_upload"), "begin_upload target mismatch")
        check(ticket.get("size") == len(data) and ticket.get("sha256") == digest
              and isinstance(ticket.get("expires_at"), str), "begin_upload echo mismatch")
        check(isinstance(ticket.get("command"), str) and "-T FILE" in ticket["command"],
              "begin_upload command lacks the -T FILE placeholder")
        self.ticket_secret(ticket)
        status, _, body = self.put_upload(ticket, path)
        view = self.uploaded_release(status, body, "archive")
        check(view.get("files") == 3, "uploaded ZIP entry count mismatch")
        for name, content in (("index.html", HTML), ("style.css", CSS), ("pixel.png", PNG)):
            self.public_bytes(view["token"], name, content)
        # The ticket was consumed by its first use.
        check(self.auth_refused(self.put_upload(ticket, path)),
              "a used upload ticket was accepted again")
        # A retry with the same idempotency key returns the same release.
        again = self.begin_upload(len(data), digest, label=label, idempotency_key=idem)
        status, _, body = self.put_upload(again, path)
        second = self.uploaded_release(status, body, "idempotent retry")
        check(second["token"] == view["token"], "upload retry created another release")

    def test_15_single_file_upload(self):
        data = os.urandom(3 << 20)
        path = self.write_fixture("report.bin", data)
        ticket = self.begin_upload(len(data), hashlib.sha256(data).hexdigest(),
                                   filename="report.bin")
        status, _, body = self.put_upload(ticket, path)
        view = self.uploaded_release(status, body, "single file")
        check(isinstance(view.get("url"), str) and view["url"].endswith("/report.bin"),
              "single-file release URL does not end with the filename")
        self.public_bytes(view["token"], "report.bin", data)

    def test_16_upload_refusals(self):
        data = os.urandom(64 << 10)
        digest = hashlib.sha256(data).hexdigest()
        path = self.write_fixture("refusal.bin", data)
        # Wrong declared SHA-256.
        ticket = self.begin_upload(len(data), "0" * 64, filename="refusal.bin")
        check(self.put_upload(ticket, path)[0] == 400, "SHA-256 mismatch was not refused with 400")
        # Declared size larger than the bytes sent.
        ticket = self.begin_upload(len(data) + 1, digest, filename="refusal.bin")
        check(self.put_upload(ticket, path)[0] == 400, "size mismatch was not refused with 400")
        # A management key is not an upload credential.
        check(self.auth_refused(self.put_upload(None, path, key=self.key)),
              "management key was accepted on /_upload")
        check(self.auth_refused(self.put_upload(None, path, anonymous=True)),
              "anonymous upload was not refused with 401")
        # A ticket is not a management credential; then use it for real to clean up.
        ticket = self.begin_upload(len(data), digest, filename="refusal.bin")
        message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                              "params": {}}).encode()
        refused = self.request("/mcp", "POST", body=message,
                               key=self.ticket_secret(ticket), headers={
                                   "Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream",
                                   "MCP-Protocol-Version": "2025-06-18"})
        check(self.auth_refused(refused), "upload ticket was accepted on /mcp")
        status, _, body = self.put_upload(ticket, path)
        self.uploaded_release(status, body, "ticket cleanup")
        # Only PUT, exact path.
        status, _, _ = self.request("/_upload", "GET", anonymous=True)
        check(status == 405, "GET /_upload was not refused with 405")
        check(self.request("/_upload?x=1", "PUT", upload=path, anonymous=True)[0] == 404,
              "PUT /_upload with a query string was not refused with 404")

    @unittest.skipUnless(os.environ.get("FSERVER_TEST_LARGE") == "1",
                         "set FSERVER_TEST_LARGE=1 for the 256 MiB upload")
    def test_17_optional_large_single_file_upload(self):
        size = 256 << 20
        path = self.work / "large.bin"
        private_write(path, b"")
        digest = hashlib.sha256()
        with path.open("wb") as out:
            left = size
            while left:
                chunk = os.urandom(min(left, 4 << 20))
                digest.update(chunk)
                out.write(chunk)
                left -= len(chunk)
        ticket = self.begin_upload(size, digest.hexdigest(), filename="large.bin")
        status, _, body = self.put_upload(ticket, path, max_time=1800)
        view = self.uploaded_release(status, body, "large file")
        check(view.get("bytes") == size, "large upload size mismatch")
        status, _, downloaded = self.request("/" + view["token"] + "/large.bin", anonymous=True,
                                             max_bytes=size + (1 << 20), as_file=True,
                                             max_time=1800)
        check(status == 200 and downloaded.stat().st_size == size, "large download failed")
        check_digest = hashlib.sha256()
        with downloaded.open("rb") as source:
            while chunk := source.read(4 << 20):
                check_digest.update(chunk)
        check(check_digest.digest() == digest.digest(), "large download hash mismatch")

    @unittest.skipUnless(os.environ.get("FSERVER_TEST_LARGE") == "1",
                         "set FSERVER_TEST_LARGE=1 for exact100MiB archive")
    def test_11_optional_large_archive(self):
        size = 100 << 20
        archive_path = self.work / "large.tar"
        payload_size = size - 1536

        class Payload:
            left = payload_size

            def read(self, n=-1):
                n = min(self.left, n if n >= 0 else self.left)
                self.left -= n
                return b"a" * n

        private_write(archive_path, b"")
        with tarfile.open(archive_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            header = tarfile.TarInfo("large.pdf")
            header.mode, header.size = 0o600, payload_size
            archive.addfile(header, Payload())
        archive_path.chmod(0o600)
        check(archive_path.stat().st_size == size, "large fixture is not exactly100MiB")
        label = self.tag + "-large"
        self.release_labels.add(label)
        body_path = self.work / "large-request.json"
        prefix = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "publish_archive", "arguments": {"label": label,
            "idempotency_key": secrets.token_urlsafe(24), "archive_base64": ""}}}
        raw = json.dumps(prefix, separators=(",", ":")).encode()
        marker = b'"archive_base64":""'
        before, after = raw.split(marker)
        fd = os.open(body_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out, archive_path.open("rb") as source:
            out.write(before + b'"archive_base64":"')
            while chunk := source.read(3 << 20):
                out.write(base64.b64encode(chunk))
            out.write(b'"' + after)
        view = self.tool("publish_archive", {}, body_file=body_path)
        check(TOKEN.fullmatch(view.get("token", "")), "large release metadata invalid")
        self.releases.add(view["token"])
        check(view.get("bytes") == payload_size, "large release size mismatch")
        message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "download_release", "arguments": {"token": view["token"]}}}).encode()
        status, _, body = self.request("/mcp", "POST", body=message, headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18"})
        check(status == 200, "large download MCP call failed")
        result = json.loads(body).get("result", {})
        text = json.dumps(result)
        check(result.get("isError") is True and "1 MiB" in text and "/_api/" not in text,
              "large download was not refused inline-only")

if __name__ == "__main__":
    program = unittest.main(testRunner=SafeRunner(verbosity=2), exit=False)
    if hasattr(MCPLive, "revocation_status"):
        print("Revoked-key authentication rejection: HTTP %d" % MCPLive.revocation_status)
    raise SystemExit(not program.result.wasSuccessful())
