#!/usr/bin/env python3
"""VM-only HTTPS management acceptance; creates/revokes its own temporary keys.

Run as the trusted owner, not root. Requires the installed CLI and sudo for log
verification. Same FSERVER_TEST_BASE/FSERVER_TEST_RESOLVE knobs as static tests.
Every test release is permanently removed via authenticated DELETE at cleanup.
Never prints credentials, visitor passwords, reset responses, or unrelated URLs.
"""
import base64

import io
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from urllib.parse import urlsplit

BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000").rstrip("/")
RESOLVE = os.environ.get("FSERVER_TEST_RESOLVE")
AS_ROOT = [] if os.geteuid() == 0 else ["sudo"]
CLI = shlex.split(os.environ.get(
    "FSERVER_TEST_PUBLISH", " ".join([*AS_ROOT, "/usr/local/bin/agent-fileserver"])))
LOG = os.environ.get("FSERVER_TEST_LOG", "/var/log/agent-fileserver/access.json")
API_UNIT = os.environ.get("FSERVER_TEST_API_UNIT", "agent-fileserver-api")
API = "/_api/v1"


class ManagementAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="fserver-api-acceptance-")
        cls.work = Path(cls.tmp.name)
        cls.tag = "https-test-" + secrets.token_hex(8)
        cls.key = cls.create_key(cls.tag)
        cls.keys = [cls.tag]
        cls.releases = set()
        cls.seq = 0
        cls.passwords = []
        cls.results = []
        cls.started = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    @classmethod
    def create_key(cls, label):
        return subprocess.check_output(
            [*CLI, "token", "create", "--label", label, "--days", "1"], text=True
        ).strip()

    @classmethod
    def tearDownClass(cls):
        errors = []
        try:
            for token in sorted(cls.releases):
                status, _, _ = cls.request(API + "/releases/" + token, "DELETE")
                if status not in (204, 404):
                    errors.append("test release cleanup failed")
        finally:
            for label in cls.keys:
                result = subprocess.run([*CLI, "token", "revoke", label],
                                        capture_output=True)
                if result.returncode:
                    errors.append("test credential revocation failed")
            cls.tmp.cleanup()
        if errors:
            raise AssertionError("; ".join(errors))

    @classmethod
    def request(cls, path, method="GET", *, data=None, content_type=None,
                auth=True, basic=None, key=None, headers=None):
        cls.seq += 1
        prefix = cls.work / ("req-" + str(cls.seq))
        hfile = prefix.with_suffix(".request-headers")
        lines = ["User-Agent: " + cls.tag, "Accept-Encoding: identity"]
        if auth:
            lines.append("Authorization: Bearer " + (key or cls.key))
        if basic is not None:
            encoded = base64.b64encode(("viewer:" + basic).encode()).decode()
            lines = [s for s in lines if not s.startswith("Authorization:")]
            lines.append("Authorization: Basic " + encoded)
        if content_type:
            lines.append("Content-Type: " + content_type)
        for name, value in (headers or {}).items():
            lines.append(name + ": " + value)
        hfile.write_text("\n".join(lines) + "\n")
        hfile.chmod(0o600)
        response_headers = prefix.with_suffix(".response-headers")
        response_body = prefix.with_suffix(".response-body")
        args = ["curl", "-q", "-sS", "--path-as-is", "--http2", "--max-time",
                "190", "--request", method, "--header", "@" + str(hfile),
                "-D", str(response_headers), "-o", str(response_body),
                "-w", "%{http_code}|%{http_version}|%{time_total}"]
        if RESOLVE:
            args += ["--resolve", RESOLVE]
        if data is not None:
            if not isinstance(data, Path):
                f = prefix.with_suffix(".request-body")
                f.write_bytes(data)
                f.chmod(0o600)
                data = f
            args += ["--data-binary", "@" + str(data)]
        result = subprocess.run(args + [BASE + path], capture_output=True,
                                text=True)
        if result.returncode:
            raise AssertionError("HTTPS transport failed (curl exit %d)" %
                                 result.returncode)
        status, version, duration = result.stdout.split("|")
        parsed = {}
        for line in response_headers.read_text().splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                parsed[name.lower()] = value.strip()
        cls.results.append((method, int(status), version, float(duration)))
        return int(status), parsed, response_body.read_bytes()

    @classmethod
    def artifact(cls, entries):
        """entries: (name, bytes|None directory), with deterministic tar bytes."""
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as t:
            for name, body in entries:
                h = tarfile.TarInfo(name)
                if body is None:
                    h.type = tarfile.DIRTYPE
                    h.mode = 0o700
                    t.addfile(h)
                else:
                    h.size = len(body)
                    h.mode = 0o600
                    t.addfile(h, io.BytesIO(body))
        cls.seq += 1
        p = cls.work / ("artifact-" + str(cls.seq) + ".tar")
        p.write_bytes(out.getvalue())
        return p

    @classmethod
    def multipart(cls, artifact, metadata):
        boundary = "fserver-" + secrets.token_hex(16)
        cls.seq += 1
        p = cls.work / ("multipart-" + str(cls.seq))
        with p.open("wb") as f:
            f.write(("--" + boundary +
                     '\r\nContent-Disposition: form-data; name="metadata"\r\n'
                     "Content-Type: application/json\r\n\r\n").encode())
            f.write(json.dumps(metadata).encode())
            f.write(("\r\n--" + boundary +
                     '\r\nContent-Disposition: form-data; name="artifact"; '
                     'filename="artifact.tar"\r\n'
                     "Content-Type: application/octet-stream\r\n\r\n").encode())
            with artifact.open("rb") as src:
                shutil.copyfileobj(src, f)
            f.write(("\r\n--" + boundary + "--\r\n").encode())
        p.chmod(0o600)
        return p, "multipart/form-data; boundary=" + boundary

    @classmethod
    def upload(cls, artifact, metadata=None, key=None):
        body, ctype = cls.multipart(artifact, metadata or {})
        status, headers, data = cls.request(
            API + "/releases", "POST", data=body, content_type=ctype,
            headers={"Idempotency-Key": key or secrets.token_urlsafe(20)})
        if status == 201:
            result = json.loads(data)
            cls.releases.add(result["token"])
        return status, headers, data

    def publish(self, entries, password=None):
        metadata = {"label": 'Test "label" $(echo bad)', "spa": False}
        if password:
            metadata["password"] = password
            self.passwords.append(password)
        status, headers, body = self.upload(self.artifact(entries), metadata)
        self.assertEqual(status, 201)
        self.assertEqual(headers["cache-control"], "no-store")
        return json.loads(body)

    def test_01_authenticated_namespace_and_management_scope(self):
        status, headers, body = self.request(API + "/me")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIsInstance(data["namespace"], str)
        self.assertTrue(data["namespace"])
        if os.environ.get("FSERVER_TEST_NAMESPACE"):
            self.assertEqual(data["namespace"], os.environ["FSERVER_TEST_NAMESPACE"])
        self.assertEqual(data["agent"], self.tag)
        self.assertEqual(data["limits"]["max_upload_bytes"], 100 << 20)
        self.assertEqual(headers["cache-control"], "no-store")
        for path in (API + "/tokens", "/_internal/authorize",
                     "/_internal/health", "/credentials/", "/policies/"):
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request(API + "/me", "POST")[0], 405)
        self.assertEqual(self.request(API + "/me", auth=False)[0], 401)
        self.assertEqual(self.request("/")[0], 404)

    def test_02_pdf_metacharacters_download_and_delete(self):
        content = b"%PDF-1.7\nHTTPS metacharacter test\n%%EOF\n"
        name = "Proposal 'v2' $(echo bad) #1 ? 50% + résumé.pdf"
        m = self.publish([(name, content)])
        url = urlsplit(m["url"])
        status, h, body = self.request(url.path, auth=False)
        self.assertEqual((status, body), (200, content))
        self.assertEqual(h["content-type"], "application/pdf")
        self.assertEqual(self.request(
            url.path, auth=False, headers={"Range": "bytes=0-7"})[2], content[:8])
        route = API + "/releases/" + m["token"]
        status, h, body = self.request(route + "/download")
        self.assertEqual((status, body), (200, content))
        self.assertIn("attachment", h["content-disposition"])
        self.assertEqual(self.request(route, "DELETE")[0], 204)
        self.releases.remove(m["token"])
        self.assertEqual(self.request(url.path, auth=False)[0], 404)
        self.assertEqual(self.request(route)[0], 404)

    def test_03_site_password_lifecycle_and_protected_assets(self):
        password = secrets.token_urlsafe(18)
        script = b'console.log("protected demo");\n' * 200
        html = b"<!doctype html><title>Protected</title><script src='./app.js'></script>"
        m = self.publish([("site/", None), ("site/index.html", html),
                          ("site/app.js", script)], password)
        root = "/" + m["token"] + "/"
        route = API + "/releases/" + m["token"]
        for suffix in ("", "app.js", "app.js.gz"):
            self.assertEqual(self.request(root + suffix, auth=False)[0], 401)
        self.assertEqual(self.request(root, auth=False, basic="wrong-password")[0],
                         401)
        self.assertEqual(self.request(root)[0], 401)  # API key is not viewer auth.
        status, h, body = self.request(root, auth=False, basic=password)
        self.assertEqual((status, body), (200, html))
        self.assertEqual(h["cache-control"], "private, no-store")
        self.assertEqual(self.request(
            root, auth=False, basic=password,
            headers={"X-Fserver-Cache-Control": "public, max-age=999999"})[1]
            ["cache-control"], "private, no-store")
        self.assertIn("noindex", h["x-robots-tag"])
        self.assertEqual(self.request(root + "app.js", auth=False,
                                      basic=password)[2], script)
        status, _, archive = self.request(route + "/download")
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as t:
            names = t.getnames()
            self.assertEqual(set(names), {"site", "site/index.html", "site/app.js"})
            self.assertEqual(t.extractfile("site/app.js").read(), script)
        # A malformed "set password" must never remove protection.
        for invalid in ({}, {"password": None}, {"password": ""}):
            self.assertEqual(self.request(
                route + "/password", "PUT", data=json.dumps(invalid).encode(),
                content_type="application/json")[0], 400)
        password2 = secrets.token_urlsafe(18)
        self.passwords.append(password2)
        self.assertEqual(self.request(
            route + "/password", "PUT",
            data=json.dumps({"password": password2}).encode(),
            content_type="application/json")[0], 200)
        self.assertEqual(self.request(root, auth=False, basic=password)[0], 401)
        self.assertEqual(self.request(root, auth=False, basic=password2)[0], 200)
        status, _, raw = self.request(route + "/password/reset", "POST")
        self.assertEqual(status, 200)
        reset = json.loads(raw)["password"]
        self.passwords.append(reset)
        self.assertEqual(self.request(root, auth=False, basic=password2)[0], 401)
        self.assertEqual(self.request(root, auth=False, basic=reset)[0], 200)
        self.assertEqual(self.request(route + "/password", "DELETE")[0], 200)
        self.assertEqual(self.request(root, auth=False)[0], 200)

    def test_04_idempotency_and_current_protection_view(self):
        artifact = self.artifact([("same.txt", b"same artifact\n")])
        key = secrets.token_urlsafe(20)
        meta = {"label": "replay"}
        s, _, first = self.upload(artifact, meta, key)
        self.assertEqual(s, 201)
        m = json.loads(first)
        route = API + "/releases/" + m["token"]
        s, _, again = self.upload(artifact, meta, key)
        self.assertEqual(s, 201)
        self.assertEqual(json.loads(again)["token"], m["token"])
        self.assertEqual(self.upload(artifact, {"label": "changed"}, key)[0], 409)
        password = secrets.token_urlsafe(18)
        self.passwords.append(password)
        self.assertEqual(self.request(
            route + "/password", "PUT",
            data=json.dumps({"password": password}).encode(),
            content_type="application/json")[0], 200)
        s, _, current = self.upload(artifact, meta, key)
        self.assertEqual(s, 201)
        self.assertTrue(json.loads(current)["protected"])
        self.assertEqual(self.request(route, "DELETE")[0], 204)
        self.releases.remove(m["token"])
        self.assertEqual(self.upload(artifact, meta, key)[0], 409)

    def test_05_tar_rejections_and_publisher_refusal(self):
        for entries in ([("../escape.txt", b"x")],
                        [("a.txt", b"x"), ("b.txt", b"y")],
                        [("root/a.txt", b"x"), ("root/a.txt", b"y")]):
            self.assertEqual(self.upload(self.artifact(entries))[0], 400)
        self.assertEqual(self.upload(self.artifact(
            [("root/.env", b"SYNTHETIC_TEST_ONLY=yes")]))[0], 422)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as t:
            h = tarfile.TarInfo("escape")
            h.type = tarfile.SYMTYPE
            h.linkname = "/etc/passwd"
            t.addfile(h)
        self.seq += 1
        artifact = self.work / ("symlink-" + str(self.seq) + ".tar")
        artifact.write_bytes(raw.getvalue())
        self.assertEqual(self.upload(artifact)[0], 400)

    def test_06_indexless_and_empty_files(self):
        m = self.publish([("documents/read me.txt", b"indexless works\n")])
        root = "/" + m["token"] + "/"
        self.assertEqual(self.request(root, auth=False)[0], 404)
        self.assertEqual(self.request(root + "read%20me.txt", auth=False)[2],
                         b"indexless works\n")
        m = self.publish([("empty.txt", b"")])
        s, _, body = self.request(urlsplit(m["url"]).path, auth=False)
        self.assertEqual((s, body), (200, b""))

    def test_07_supported_100_mib_wire_limit(self):
        maximum = 100 << 20

        class Zeros:
            remaining = maximum - 1536

            def read(self, n=-1):
                n = min(n if n >= 0 else self.remaining, self.remaining)
                self.remaining -= n
                return b"\0" * n

        archive = self.work / "maximum.tar"
        with tarfile.open(archive, mode="w", format=tarfile.USTAR_FORMAT) as t:
            h = tarfile.TarInfo("large.bin")
            h.size = maximum - 1536
            t.addfile(h, Zeros())
        self.assertEqual(archive.stat().st_size, maximum)
        s, _, raw = self.upload(archive, {"label": "100MiB boundary test"})
        self.assertEqual(s, 201)
        m = json.loads(raw)
        self.assertEqual(m["bytes"], maximum - 1536)
        path = urlsplit(m["url"]).path
        s, _, body = self.request(path, auth=False,
                                  headers={"Range": "bytes=0-255"})
        self.assertEqual((s, body), (206, b"\0" * 256))
        self.assertEqual(self.request(
            API + "/releases/" + m["token"], "DELETE")[0], 204)
        self.releases.remove(m["token"])
        with archive.open("ab") as f:
            f.write(b"\0")
        self.assertEqual(self.upload(archive)[0], 413)
        print("PASS supported boundary: 100 MiB tar accepted; +1 byte rejected")

    def test_08_individual_key_revocation(self):
        label = self.tag + "-revocation"
        raw = self.create_key(label)
        self.keys.append(label)
        self.assertEqual(self.request(API + "/me", key=raw)[0], 200)
        subprocess.run([*CLI, "token", "revoke", label], check=True,
                       capture_output=True)
        self.assertEqual(self.request(API + "/me", key=raw)[0], 401)
        self.assertEqual(self.request(API + "/me")[0], 200)

    def test_09_logs_do_not_contain_credentials(self):
        access = subprocess.check_output(
            [*AS_ROOT, "cat", LOG], text=True)
        journal = subprocess.check_output(
            [*AS_ROOT, "journalctl", "-u", API_UNIT, "--since", self.started,
             "-o", "cat", "--no-pager"], text=True)
        for secret in [self.key, *self.passwords]:
            self.assertTrue(secret not in access, "credential leaked in access log")
            self.assertTrue(secret not in journal, "credential leaked in journal")
            basic = base64.b64encode(("viewer:" + secret).encode()).decode()
            self.assertTrue(basic not in access, "Basic credential leaked in access log")
            self.assertTrue(basic not in journal, "Basic credential leaked in journal")
        matching = [json.loads(s) for s in access.splitlines() if self.tag in s]
        self.assertTrue(matching)
        self.assertTrue(all(e["request"]["headers"].get("Authorization") in
                            (None, ["REDACTED"]) for e in matching))

    def test_10_auth_throttle_does_not_lock_out_a_valid_key(self):
        statuses = []
        for n in range(12):
            headers = {"X-Fserver-Client-IP": "198.51.100." + str(n + 1)}
            if urlsplit(BASE).scheme == "https":
                # The real edge appends the true IP. A local owner-shell caller
                # is itself a trusted proxy peer, so local XFF is not untrusted.
                headers["X-Forwarded-For"] = "203.0.113." + str(n + 1)
            statuses.append(self.request(
                API + "/me", key="not-a-real-key", headers=headers)[0])
        self.assertIn(429, statuses)
        self.assertEqual(self.request(API + "/me")[0], 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
