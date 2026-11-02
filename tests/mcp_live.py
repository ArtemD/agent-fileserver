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
Flat tar.gz sites (also with ./ prefixes) publish through MCP and upload tickets,
and refused archives return typed errors with entry/reason/hint (issue #11).
Release lifecycle (issues #19-#22): default and explicit expiry with set_expiry,
update in place with token, the disk block in server_info, the list_releases
totals object and the public Cache-Control. Real expiry deletion is covered by
Go tests, not here. FSERVER_TEST_DEFAULT_EXPIRY_DAYS (default 60, the compose
default) is the default_expiry_days this stack is expected to report.
Set FSERVER_TEST_LARGE=1 for an additional exact-100-MiB decoded archive check
and a 256 MiB single-file upload/download round trip.
"""

import base64
from datetime import datetime, timedelta, timezone
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
import lzma
import tarfile
import tempfile
import unittest
from urllib.parse import urlsplit
import zipfile
import zlib


BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000").rstrip("/")
RESOLVE = os.environ.get("FSERVER_TEST_RESOLVE")
EXPECT_EXPIRY_DAYS = int(os.environ.get("FSERVER_TEST_DEFAULT_EXPIRY_DAYS", "60"))
CLI = shlex.split(os.environ.get("FSERVER_TEST_ADMIN", "docker compose run --rm -T admin"))
TOKEN = re.compile(r"[A-Za-z0-9_-]{22}\Z")
KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
HTML = b"<!doctype html><title>MCP fixture</title><h1>Published through MCP</h1>"
CSS = b"body { color: #123456; background: white; }\n"
ROBOTS = b"User-agent: *\nDisallow:\n"


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
                    if isinstance(items, dict) and isinstance(items.get("releases"), list):
                        for item in items["releases"]:
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
    def tool_error(cls, name, arguments):
        """Call a tool that must be refused; return the parsed JSON error body."""
        result = cls.rpc("tools/call", {"name": name, "arguments": arguments})
        check(isinstance(result, dict) and result.get("isError") is True,
              "MCP tool was not refused: " + name)
        contents = result.get("content", [])
        check(len(contents) == 1 and contents[0].get("type") == "text",
              "MCP error result shape mismatch")
        try:
            body = json.loads(contents[0]["text"])
        except (ValueError, KeyError, TypeError):
            raise LiveFailure("MCP error result is not JSON") from None
        check(isinstance(body, dict) and isinstance(body.get("error"), str),
              "MCP error body lacks an error string")
        check(isinstance(body.get("hint"), str) and body["hint"].strip(),
              "MCP error body lacks a hint: " + body["error"])
        return body

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

    # publish_limit is 30 publishes per key per hour and the whole suite
    # publishes more, so the lifecycle tests (24 and up) use their own key.
    # Keys manage the whole installation, so cleanup works with either.
    def setUp(self):
        number = self._testMethodName.split("_")[1]
        if number.isdigit() and int(number) >= 24:
            cls = type(self)
            if not getattr(cls, "lifecycle_key", None):
                cls.lifecycle_key = cls.create_key(cls.tag + "-lifecycle")
            main = cls.key
            cls.key = cls.lifecycle_key
            self.addCleanup(setattr, cls, "key", main)

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
                    "set_password", "reset_password", "remove_password", "begin_upload",
                    "set_expiry"}
        check(expected <= tools.keys(), "required MCP tools missing")
        for name in ("publish_files", "publish_archive", "remove_password", "begin_upload"):
            check(tools[name].get("annotations", {}).get("openWorldHint") is True,
                  "public side-effect annotation missing")
        # Publishing can replace a release's content (token), so it is destructive.
        for name in ("publish_files", "publish_archive", "begin_upload"):
            annotations = tools[name].get("annotations", {})
            check(annotations.get("destructiveHint") is True
                  and annotations.get("readOnlyHint") is not True,
                  "publish tool is not annotated destructive (it can replace content)")
            properties = tools[name].get("inputSchema", {}).get("properties", {})
            check("token" in properties and "expires_in_days" in properties,
                  "publish tool lacks token or expires_in_days arguments: " + name)
        annotations = tools["set_expiry"].get("annotations", {})
        check(annotations.get("destructiveHint") is True
              and annotations.get("readOnlyHint") is not True
              and annotations.get("openWorldHint") is not True,
              "set_expiry annotations mismatch (destructive, not read-only, not open-world)")
        check(set(tools["set_expiry"].get("inputSchema", {}).get("required", []))
              == {"token", "expires_in_days"}, "set_expiry required arguments mismatch")
        me = self.tool("server_info", {})
        check(me.get("agent") == self.tag and me.get("namespace"),
              "authenticated MCP identity mismatch")
        check(isinstance(me.get("version"), str) and me["version"],
              "server_info version missing")
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
        check(info.get("token") == view["token"] and isinstance(items, dict)
              and isinstance(items.get("releases"), list)
              and any(item.get("token") == view["token"] for item in items["releases"]),
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
    def begin_upload(cls, size, digest, *, filename=None, label=None, idempotency_key=None,
                     **extra):
        label = label or cls.tag + "-upload-" + secrets.token_hex(4)
        cls.release_labels.add(label)
        args = {"size": size, "sha256": digest, "label": label,
                "idempotency_key": idempotency_key or secrets.token_urlsafe(24), **extra}
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

    @staticmethod
    def flat_tar_gz(prefix=""):
        """A flat site as tar.gz; prefix "./" imitates `tar -czf site.tar.gz -C dir .`."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            if prefix:
                root = tarfile.TarInfo(".")
                root.type, root.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(root)
            for name, content in (("index.html", HTML), ("robots.txt", ROBOTS)):
                info = tarfile.TarInfo(prefix + name)
                info.size, info.mode = len(content), 0o644
                archive.addfile(info, io.BytesIO(content))
        return buffer.getvalue()

    def test_18_flat_tar_gz_publish_archive(self):
        # Issue #11: flat tar/tar.gz sites were refused as "malformed or unsafe".
        for suffix, prefix in (("flat", ""), ("dotslash", "./")):
            label = self.tag + "-tar-" + suffix
            self.release_labels.add(label)
            view = self.publish("publish_archive", args={
                "label": label, "idempotency_key": secrets.token_urlsafe(24),
                "archive_base64": base64.b64encode(self.flat_tar_gz(prefix)).decode()})
            check(view.get("files") == 2, "flat tar.gz entry count mismatch: " + suffix)
            self.public_bytes(view["token"], "index.html", HTML)
            self.public_bytes(view["token"], "robots.txt", ROBOTS)
            self.tool("delete_release", {"token": view["token"]})
            self.releases.discard(view["token"])
            check(self.request("/" + view["token"] + "/index.html", anonymous=True)[0] == 404,
                  "deleted tar.gz release remains public: " + suffix)

    def test_19_flat_tar_gz_upload_ticket(self):
        data = self.flat_tar_gz("./")
        path = self.write_fixture("upload-site.tar.gz", data)
        ticket = self.begin_upload(len(data), hashlib.sha256(data).hexdigest())
        status, _, body = self.put_upload(ticket, path)
        view = self.uploaded_release(status, body, "flat tar.gz")
        check(view.get("files") == 2, "uploaded flat tar.gz entry count mismatch")
        self.public_bytes(view["token"], "index.html", HTML)
        self.public_bytes(view["token"], "robots.txt", ROBOTS)
        self.tool("delete_release", {"token": view["token"]})
        self.releases.discard(view["token"])

    def test_20_unsafe_archive_entry_is_named(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in (("index.html", HTML), ("../evil.html", HTML)):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(content), 0o644
                archive.addfile(info, io.BytesIO(content))
        error = self.tool_error("publish_archive", {
            "label": self.tag + "-unsafe", "idempotency_key": secrets.token_urlsafe(24),
            "archive_base64": base64.b64encode(buffer.getvalue()).decode()})
        check(error["error"] == "unsafe archive entry", "unsafe entry error string mismatch")
        check(error.get("entry") == "../evil.html", "unsafe entry was not named")
        check(isinstance(error.get("reason"), str) and error["reason"].strip(),
              "unsafe entry error lacks a reason")

    def test_21_malformed_archive_has_reason_and_hint(self):
        error = self.tool_error("publish_archive", {
            "label": self.tag + "-malformed", "idempotency_key": secrets.token_urlsafe(24),
            "archive_base64": base64.b64encode(b"this is not an archive " * 40).decode()})
        check(error["error"] == "malformed archive", "malformed archive error string mismatch")
        check(isinstance(error.get("reason"), str) and error["reason"].strip(),
              "malformed archive error lacks a reason")

    def test_22_unsupported_format_is_named(self):
        # Issue #12: known but unsupported containers are named, not "malformed".
        packed = lzma.compress(self.flat_tar_gz(), format=lzma.FORMAT_XZ)
        error = self.tool_error("publish_archive", {
            "label": self.tag + "-xz", "idempotency_key": secrets.token_urlsafe(24),
            "archive_base64": base64.b64encode(packed).decode()})
        check(error["error"] == "unsupported archive format", "xz error string mismatch")
        check("detected xz" in error.get("reason", ""), "xz was not named in the reason")

    def test_23_single_index_html_is_a_page(self):
        # Issue #13: a lone index.html is a one-page site served at the root.
        path = self.write_fixture("index.html", HTML)
        ticket = self.begin_upload(len(HTML), hashlib.sha256(HTML).hexdigest(), filename="index.html")
        status, _, body = self.put_upload(ticket, path)
        view = self.uploaded_release(status, body, "single index.html")
        check(view.get("url", "").endswith("/" + view["token"] + "/"),
              "single index.html release does not report the root URL")
        for relative in ("", "index.html"):
            status, headers, data = self.request("/" + view["token"] + "/" + relative, anonymous=True)
            check(status == 200 and data == HTML, "single index.html not served: /" + relative)
            check(headers.get("content-type", "").startswith("text/html")
                  and "content-disposition" not in headers,
                  "single index.html is not served inline as HTML: /" + relative)
        self.tool("delete_release", {"token": view["token"]})
        self.releases.discard(view["token"])

    @classmethod
    def site_args(cls, **extra):
        """Arguments for a two-file publish_files call with a tracked, unique label."""
        label = cls.tag + "-" + secrets.token_hex(6)
        cls.release_labels.add(label)
        return {"label": label, "idempotency_key": secrets.token_urlsafe(24),
                "files": [{"path": "index.html", "text": HTML.decode()},
                          {"path": "assets/style.css", "text": CSS.decode()}], **extra}

    @staticmethod
    def parse_time(value, stage):
        """RFC 3339 UTC timestamp (Go may print any number of fraction digits)."""
        match = (re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)", value)
                 if isinstance(value, str) else None)
        check(match, stage + ": timestamp missing or malformed")
        zone = "+00:00" if match.group(2) == "Z" else match.group(2)
        return datetime.fromisoformat(match.group(1) + zone)

    def check_expiry(self, view, days, stage):
        """expires_at is always present: null for never, else about `days` days ahead."""
        check("expires_at" in view, stage + ": expires_at missing")
        if days == 0:
            check(view["expires_at"] is None, stage + ": expected a release that never expires")
            return
        expected = datetime.now(timezone.utc) + timedelta(days=days)
        actual = self.parse_time(view["expires_at"], stage)
        check(abs(actual - expected) < timedelta(hours=6),
              stage + ": expires_at is not about %d days ahead" % days)

    @staticmethod
    def check_notice(view, stage):
        notice = view.get("notice")
        check(isinstance(notice, str) and "set_expiry" in notice,
              stage + ": notice missing or does not mention set_expiry")

    def test_24_server_info_default_expiry_and_disk(self):
        me = self.tool("server_info", {})
        check(me.get("default_expiry_days") == EXPECT_EXPIRY_DAYS,
              "server_info default_expiry_days is not the expected %d" % EXPECT_EXPIRY_DAYS)
        disk = me.get("disk")
        ints = ("free_bytes", "total_bytes", "reserve_bytes", "available_bytes",
                "largest_file_upload_bytes", "largest_archive_upload_bytes")
        check(isinstance(disk, dict) and all(type(disk.get(field)) is int and disk[field] >= 0
                                             for field in ints),
              "server_info disk block missing or has non-integer fields")
        check(type(disk.get("inline_publish_ok")) is bool, "disk.inline_publish_ok is not a boolean")
        check(disk.get("free_inodes") is None
              or (type(disk["free_inodes"]) is int and disk["free_inodes"] >= 0),
              "disk.free_inodes is neither null nor a count")
        check(0 < disk["total_bytes"] and disk["free_bytes"] <= disk["total_bytes"],
              "disk free/total bytes are inconsistent")
        check(disk["available_bytes"] <= disk["free_bytes"]
              and disk["available_bytes"] == max(disk["free_bytes"] - disk["reserve_bytes"], 0),
              "disk.available_bytes is not free_bytes above the reserve")
        maximum = me["upload"]["max_bytes"]
        check(disk["largest_file_upload_bytes"] <= maximum
              and disk["largest_archive_upload_bytes"] <= maximum,
              "a disk largest_* value exceeds the upload max_bytes")
        check(disk["largest_file_upload_bytes"] <= disk["available_bytes"] // 5,
              "disk.largest_file_upload_bytes exceeds one fifth of available_bytes")
        check(disk["largest_archive_upload_bytes"] <= disk["available_bytes"],
              "disk.largest_archive_upload_bytes exceeds available_bytes")

    def test_25_expiry_default_explicit_and_set_expiry(self):
        default = self.tool("server_info", {})["default_expiry_days"]
        view = self.publish()
        self.check_expiry(view, default, "default publish")
        self.check_notice(view, "default publish")
        info = self.tool("release_info", {"token": view["token"]})
        check(info.get("expires_at") == view["expires_at"] and "notice" not in info,
              "release_info expiry mismatch or unexpected notice")
        # expires_in_days 0 means never; a number counts from now.
        never = self.publish(args=self.site_args(expires_in_days=0))
        self.check_expiry(never, 0, "expires_in_days 0")
        self.check_notice(never, "expires_in_days 0")
        short = self.publish(args=self.site_args(expires_in_days=5))
        self.check_expiry(short, 5, "expires_in_days 5")
        # set_expiry changes it and 0 removes it.
        token = view["token"]
        changed = self.tool("set_expiry", {"token": token, "expires_in_days": 30})
        check(changed.get("token") == token, "set_expiry returned another release")
        self.check_expiry(changed, 30, "set_expiry 30")
        self.check_notice(changed, "set_expiry 30")
        info = self.tool("release_info", {"token": token})
        check(info.get("expires_at") == changed["expires_at"], "set_expiry was not stored")
        removed = self.tool("set_expiry", {"token": token, "expires_in_days": 0})
        self.check_expiry(removed, 0, "set_expiry 0")
        self.check_notice(removed, "set_expiry 0")
        check(self.tool("release_info", {"token": token}).get("expires_at") is None,
              "set_expiry 0 did not remove the expiry")
        again = self.tool("set_expiry", {"token": token, "expires_in_days": 7})
        self.check_expiry(again, 7, "set_expiry 7")
        # The release stays online while it has an expiry in the future.
        self.public_bytes(token, "index.html", HTML)

    def test_26_expiry_refusals_have_hints(self):
        view = self.publish(args=self.site_args(expires_in_days=0))
        token = view["token"]
        message = "expires_in_days must be an integer from 0 to 3650"
        for days in (3651, -1):
            error = self.tool_error("set_expiry", {"token": token, "expires_in_days": days})
            check(error["error"] == message, "set_expiry out-of-range error string mismatch")
        check(self.tool_error("publish_files", self.site_args(expires_in_days=3651))["error"]
              == message, "publish_files out-of-range expires_in_days error string mismatch")
        ticket_error = self.tool_error("begin_upload", {
            "size": 1, "sha256": "0" * 64, "label": self.tag + "-refused",
            "idempotency_key": secrets.token_urlsafe(24), "expires_in_days": 3651})
        check(ticket_error["error"] == message, "begin_upload out-of-range error string mismatch")
        check(self.tool("release_info", {"token": token}).get("expires_at") is None,
              "a refused set_expiry changed the release")
        check(self.tool_error("set_expiry", {"token": token})["error"]
              == "invalid set_expiry arguments", "set_expiry without days was not refused")
        check(self.tool_error("set_expiry", {"token": "short", "expires_in_days": 1})["error"]
              == "invalid set_expiry arguments", "set_expiry with a malformed token was not refused")
        unknown = secrets.token_urlsafe(16)
        check(TOKEN.fullmatch(unknown), "test token generator is broken")
        check(self.tool_error("set_expiry", {"token": unknown, "expires_in_days": 1})["error"]
              == "release not found", "set_expiry on an unknown release was not a 404")

    def test_27_update_in_place_keeps_token_and_url(self):
        first = self.publish()
        token = first["token"]
        check("updated_at" not in first, "a new release already has updated_at")
        self.public_bytes(token, "index.html", HTML)
        self.public_bytes(token, "assets/style.css", CSS)
        page = b"<!doctype html><title>Updated</title><h1>Updated in place " + secrets.token_hex(4).encode() + b"</h1>"
        key = secrets.token_urlsafe(24)
        args = {"token": token, "idempotency_key": key,
                "files": [{"path": "index.html", "text": page.decode()}]}
        updated = self.publish(args=args)
        check(updated["token"] == token and updated.get("url") == first.get("url"),
              "update changed the token or URL")
        check(updated.get("created_at") == first.get("created_at"), "update changed created_at")
        self.parse_time(updated.get("updated_at"), "update")
        check(updated.get("label") == first.get("label"), "update without label changed the label")
        check(updated.get("files") == 1 and updated.get("bytes") == len(page),
              "update did not report the new content")
        check(updated.get("expires_at") == first.get("expires_at"),
              "update without expires_in_days changed the expiry")
        self.check_notice(updated, "update")
        # The same URL now serves the new content; the old files are gone.
        self.public_bytes(token, "", page)
        self.public_bytes(token, "index.html", page)
        check(self.request("/" + token + "/assets/style.css", anonymous=True)[0] == 404,
              "an old file survived the update")
        info = self.tool("release_info", {"token": token})
        self.parse_time(info.get("updated_at"), "release_info")
        check(info.get("created_at") == first.get("created_at"), "release_info created_at changed")
        # Exact retry returns the same release; the same key for another release is refused.
        replay = self.tool("publish_files", args)
        check(replay.get("token") == token and replay.get("updated_at") == updated.get("updated_at"),
              "update retry did not replay the first result")
        other = self.publish()
        error = self.tool_error("publish_files", {**args, "token": other["token"]})
        check(error["error"] == "idempotency key was used with a different body",
              "the same idempotency_key with another token was not refused")
        self.public_bytes(other["token"], "index.html", HTML)
        # expires_in_days on an update replaces the expiry; omitted keeps it.
        args = {"token": token, "idempotency_key": secrets.token_urlsafe(24), "expires_in_days": 0,
                "files": [{"path": "index.html", "text": page.decode()}]}
        check(self.publish(args=args).get("expires_at") is None, "update did not remove the expiry")
        args = {"token": token, "idempotency_key": secrets.token_urlsafe(24),
                "files": [{"path": "index.html", "text": page.decode()}]}
        check(self.publish(args=args).get("expires_at") is None, "update without days changed the expiry")

    def test_28_update_keeps_the_access_policy(self):
        password = secrets.token_urlsafe(24)
        view = self.publish(password=password)
        token = view["token"]
        check(view.get("protected") is True, "password publish is not protected")
        page = b"<!doctype html><title>Private update</title><h1>" + secrets.token_hex(4).encode() + b"</h1>"
        updated = self.publish(args={"token": token, "idempotency_key": secrets.token_urlsafe(24),
                                     "files": [{"path": "index.html", "text": page.decode()}]})
        check(updated["token"] == token and updated.get("protected") is True,
              "an update without a password made the release public")
        check(self.request("/" + token + "/", anonymous=True)[0] == 401,
              "an updated protected release is public")
        self.public_bytes(token, "", page, password=password)
        # A new password on an update replaces the old one.
        replacement = secrets.token_urlsafe(24)
        self.publish(args={"token": token, "password": replacement,
                           "idempotency_key": secrets.token_urlsafe(24),
                           "files": [{"path": "index.html", "text": page.decode()}]})
        check(self.request("/" + token + "/", password=password)[0] == 401,
              "the old visitor password survived an update with a new one")
        self.public_bytes(token, "", page, password=replacement)

    def test_29_update_errors_and_upload_ticket_update(self):
        unknown = secrets.token_urlsafe(16)
        files = [{"path": "index.html", "text": HTML.decode()}]
        error = self.tool_error("publish_files", {
            "token": unknown, "idempotency_key": secrets.token_urlsafe(24), "files": files})
        check(error["error"] == "release not found", "update of an unknown release was not a 404")
        error = self.tool_error("publish_files", {
            "token": "short", "idempotency_key": secrets.token_urlsafe(24), "files": files})
        check(error["error"] == "invalid release token", "malformed update token was not refused")
        error = self.tool_error("begin_upload", {
            "size": len(HTML), "sha256": hashlib.sha256(HTML).hexdigest(), "filename": "index.html",
            "token": unknown, "label": self.tag + "-unknown", "idempotency_key": secrets.token_urlsafe(24)})
        check(error["error"] == "release not found",
              "begin_upload for an unknown release was not refused before minting a ticket")
        # A ticket updates a release too: same token and URL, new bytes.
        first = self.publish()
        token = first["token"]
        page = b"<!doctype html><title>Uploaded</title><h1>Uploaded update " + secrets.token_hex(4).encode() + b"</h1>"
        path = self.write_fixture("update-index.html", page)
        ticket = self.begin_upload(len(page), hashlib.sha256(page).hexdigest(),
                                   filename="index.html", token=token, label=first["label"])
        status, _, body = self.put_upload(ticket, path)
        view = self.uploaded_release(status, body, "update through ticket")
        check(view["token"] == token and view.get("url") == first.get("url"),
              "ticket update changed the token or URL")
        self.parse_time(view.get("updated_at"), "ticket update")
        self.check_notice(view, "ticket update")
        self.public_bytes(token, "", page)
        check(self.request("/" + token + "/assets/style.css", anonymous=True)[0] == 404,
              "an old file survived the ticket update")

    def test_30_public_release_cache_control_revalidates(self):
        view = self.publish()
        token = view["token"]
        for relative in ("", "index.html", "assets/style.css"):
            status, headers, _ = self.request("/" + token + "/" + relative, anonymous=True)
            check(status == 200 and headers.get("cache-control") == "public, no-cache",
                  "public release Cache-Control is not exactly 'public, no-cache': /" + relative)
            check(not relative or bool(headers.get("etag")),
                  "public release lacks an ETag: /" + relative)
        password = secrets.token_urlsafe(24)
        protected = self.publish(password=password)
        status, headers, _ = self.request("/" + protected["token"] + "/index.html", password=password)
        check(status == 200 and headers.get("cache-control") == "private, no-store",
              "protected release Cache-Control is not 'private, no-store'")

    def release_totals(self):
        result = self.tool("list_releases", {})
        check(isinstance(result, dict) and isinstance(result.get("releases"), list),
              "list_releases is not an object with releases")
        for field in ("count", "total_bytes", "expiring_within_7_days"):
            check(type(result.get(field)) is int and result[field] >= 0,
                  "list_releases " + field + " is not a non-negative integer")
        check(type(result.get("truncated")) is bool, "list_releases truncated is not a boolean")
        check(result["truncated"] == (result["count"] > len(result["releases"])),
              "list_releases truncated does not match count")
        return result

    def test_31_list_releases_totals(self):
        before = self.release_totals()
        view = self.publish(args=self.site_args(expires_in_days=0))
        token = view["token"]
        after = self.release_totals()
        check(after["count"] == before["count"] + 1 and after["count"] >= 1,
              "list_releases count did not grow by one release")
        check(after["total_bytes"] - before["total_bytes"] == view["bytes"]
              and after["total_bytes"] >= view["bytes"],
              "list_releases total_bytes did not grow by the published bytes")
        if after["count"] <= 1000:
            check(after["truncated"] is False, "list_releases is truncated below 1000 releases")
        mine = [item for item in after["releases"] if item.get("token") == token]
        check(len(mine) == 1 and "expires_at" in mine[0] and mine[0]["expires_at"] is None
              and "notice" not in mine[0], "list_releases entry lacks expires_at or has a notice")
        check(after["expiring_within_7_days"] == before["expiring_within_7_days"],
              "a never-expiring release counts as expiring")
        # Within 7 days counts; further out does not; 0 does not.
        self.tool("set_expiry", {"token": token, "expires_in_days": 3})
        soon = self.release_totals()
        check(soon["expiring_within_7_days"] == after["expiring_within_7_days"] + 1,
              "a release expiring in 3 days is not counted in expiring_within_7_days")
        self.tool("set_expiry", {"token": token, "expires_in_days": 30})
        later = self.release_totals()
        check(later["expiring_within_7_days"] == after["expiring_within_7_days"],
              "a release expiring in 30 days is counted in expiring_within_7_days")
        self.tool("delete_release", {"token": token})
        self.releases.discard(token)
        gone = self.release_totals()
        check(gone["count"] == before["count"] and gone["total_bytes"] == before["total_bytes"],
              "list_releases totals did not return to the start after the delete")

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
