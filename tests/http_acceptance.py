#!/usr/bin/env python3
"""One-shot acceptance tests; never a web server or runtime dependency.

Run: python3 tests/http_acceptance.py
Public edge: FSERVER_TEST_BASE=https://files.example.com \
  FSERVER_TEST_RESOLVE=files.example.com:443:PUBLIC_DNS_IP python3 tests/http_acceptance.py
"""
import concurrent.futures
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit

from mcp_fixture import MCPFixture

BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000").rstrip("/")
RESOLVE = os.environ.get("FSERVER_TEST_RESOLVE")


class Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="fserver-acceptance-")
        cls.work = Path(cls.temp.name)
        # Releases are created exactly as agents create them: through MCP.
        cls.mcp = MCPFixture(BASE, RESOLVE, prefix="http-acceptance")
        cls.site = cls.work / "site"
        cls.site.mkdir()
        (cls.site / "index.html").write_text(
            "<!doctype html><title>Fserver acceptance</title>"
            "<h1 id='ok'>Static server works</h1><script src='./app.js'></script>"
        )
        cls.js = b"window.FSERVER_ACCEPTANCE = true;\n" * 5000
        (cls.site / "app.js").write_bytes(cls.js)
        (cls.site / "empty").mkdir()
        cls.release = cls.publish(cls.site)
        cls.path = "/" + cls.release["token"] + "/"
        cls.spa = cls.publish(cls.site, spa=True)
        cls.spa_path = "/" + cls.spa["token"] + "/"
        cls.pdf = cls.work / "Proposal with spaces.pdf"
        cls.pdf_bytes = b"%PDF-1.7\n% Static file acceptance fixture\n%%EOF\n"
        cls.pdf.write_bytes(cls.pdf_bytes)
        cls.document = cls.publish(cls.pdf)

    @classmethod
    def publish(cls, source, spa=False):
        return cls.mcp.publish(source, spa=spa)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.mcp.close()
        finally:
            cls.temp.cleanup()

    def request(self, path, *args):
        with tempfile.TemporaryDirectory(prefix="fserver-http-") as folder:
            headers, body = Path(folder) / "headers", Path(folder) / "body"
            cmd = ["curl", "--silent", "--show-error", "--path-as-is",
                   "--max-time", "20", "--http2", "-D", str(headers),
                   "-o", str(body), "-w", "%{http_code}|%{http_version}"]
            if RESOLVE:
                cmd.extend(["--resolve", RESOLVE])
            result = subprocess.run(
                [*cmd, *args, BASE + path], capture_output=True, text=True, check=True
            )
            status, version = result.stdout.split("|")
            raw = headers.read_text()
            parsed = {}
            for line in raw.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed[k.lower()] = v.strip()
            return int(status), parsed, body.read_bytes() if body.exists() else b"", version

    def test_root_404_no_listing(self):
        status, headers, body, _ = self.request("/")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"Not Found")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn(self.release["token"].encode(), body)

    def test_invalid_and_unknown_tokens(self):
        for path in ("/foo/", "/AAAAAAAAAAAAAAAAAAAAAA/", "/sitemap.xml",
                     "/manifests/", "/staging/", "/trash/"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_robots_real_newlines(self):
        status, _, body, _ = self.request("/robots.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode().splitlines(), ["User-agent: *", "Disallow: /"])

    def test_noindex_and_referrer_and_nosniff(self):
        for path in ("/", self.path, self.path + "app.js", "/robots.txt"):
            with self.subTest(path=path):
                _, headers, _, _ = self.request(path)
                self.assertIn("noindex", headers["x-robots-tag"])
                self.assertIn("nofollow", headers["x-robots-tag"])
                self.assertEqual(headers["referrer-policy"], "no-referrer")
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                self.assertNotIn("server", headers)

    def test_index_and_js_mime(self):
        status, headers, body, _ = self.request(self.path)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["content-type"])
        self.assertIn(b"Static server works", body)
        status, headers, body, _ = self.request(self.path + "app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["content-type"])
        self.assertEqual(body, self.js)

    def test_no_directory_listing(self):
        self.assertEqual(self.request(self.path + "empty/")[0], 404)
        self.assertEqual(self.request(self.path + "empty")[0], 404)
        self.assertEqual(self.request(self.spa_path + "empty/")[0], 404)

    def test_missing_files_never_fall_back_by_default(self):
        for path in ("missing", "missing.js", "missing.css", "missing.pdf"):
            with self.subTest(path=path):
                status, headers, _, _ = self.request(self.path + path)
                self.assertEqual(status, 404)
                self.assertEqual(headers["cache-control"], "no-store")

    def test_spa_is_opt_in_and_missing_assets_still_404(self):
        self.assertEqual(self.request(self.spa_path + "client/route")[0], 200)
        self.assertEqual(self.request(self.spa_path + "missing.js")[0], 404)
        self.assertEqual(self.request("/BBBBBBBBBBBBBBBBBBBBBB/route")[0], 404)
        self.assertEqual(self.request(self.path + "client/route")[0], 404)

    def test_hidden_files_and_traversal(self):
        for suffix in (".fserver-spa", ".env", ".git/config", "%2eenv",
                       "script.php", "key.pem", "source.js.map",
                       "../../etc/passwd", "%2e%2e/%2e%2e/etc/passwd"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.request(self.spa_path + suffix)[0], 404)

    def test_gzip_precompressed(self):
        status, headers, body, _ = self.request(
            self.path + "app.js", "-H", "Accept-Encoding: gzip")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertIn("Accept-Encoding".lower(), headers["vary"].lower())
        self.assertEqual(gzip.decompress(body), self.js)
        self.assertLess(len(body), len(self.js) // 10)

    def test_brotli_precompressed(self):
        status, headers, body, _ = self.request(
            self.path + "app.js", "-H", "Accept-Encoding: br")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-encoding"], "br")
        decoded = subprocess.run(["brotli", "-d", "-c"], input=body,
                                 capture_output=True, check=True).stdout
        self.assertEqual(decoded, self.js)
        self.assertLess(len(body), len(self.js) // 10)

    def test_etag_304_and_caching(self):
        _, headers, _, _ = self.request(self.path + "app.js")
        self.assertEqual(headers["cache-control"], "public, max-age=3600")
        etag = headers["etag"]
        status, _, body, _ = self.request(
            self.path + "app.js", "-H", "If-None-Match: " + etag)
        self.assertEqual(status, 304)
        self.assertEqual(body, b"")

    def test_pdf_with_spaces_and_ranges(self):
        path = urlsplit(self.document["url"]).path
        status, headers, body, _ = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/pdf")
        self.assertEqual(body, self.pdf_bytes)
        status, headers, body, _ = self.request(path, "-H", "Range: bytes=0-7")
        self.assertEqual(status, 206)
        self.assertEqual(body, self.pdf_bytes[:8])
        self.assertIn("bytes 0-7/", headers["content-range"])
        self.assertEqual(self.request("/" + self.document["token"] + "/")[0], 404)

    def test_head_and_write_methods(self):
        result = subprocess.run(["curl", "-sSI", BASE + self.path],
                                capture_output=True, text=True, check=True) if not RESOLVE else \
                 subprocess.run(["curl", "-sSI", "--resolve", RESOLVE, BASE + self.path],
                                capture_output=True, text=True, check=True)
        self.assertIn("200", result.stdout.splitlines()[0])
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, _, _ = self.request(self.path, "-X", method)
                self.assertEqual(status, 405)
                self.assertEqual(headers["allow"], "GET, HEAD")

    def test_unique_immutable_publish_and_unpublish(self):
        first = self.publish(self.site)
        second = self.publish(self.site)
        self.assertNotEqual(first["token"], second["token"])
        self.assertRegex(first["token"], r"^[A-Za-z0-9_-]{22}$")
        token = first["token"]
        self.mcp.delete(token)
        self.assertEqual(self.request("/" + token + "/")[0], 404)
        self.assertEqual(self.request("/" + second["token"] + "/")[0], 200)

    def test_parallel_reads(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.request(self.path + "app.js")[0],
                                    range(36)))
        self.assertTrue(all(status == 200 for status in results))

    def test_public_edge_http2_and_https(self):
        if not BASE.startswith("https://"):
            self.skipTest("Use FSERVER_TEST_BASE=https://YOUR_HOST for edge test")
        status, headers, _, version = self.request(self.path)
        self.assertEqual(status, 200)
        self.assertEqual(version, "2")
        self.assertIn("strict-transport-security", headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
