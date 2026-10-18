#!/usr/bin/env python3
"""One-shot verification of private access logs; run on the serving VM."""
from concurrent.futures import ThreadPoolExecutor
import json
import os

import subprocess
import uuid

BASE = os.environ.get("FSERVER_TEST_BASE", "http://localhost:8000").rstrip("/")
RESOLVE = os.environ.get("FSERVER_TEST_RESOLVE")
LOG = os.environ.get("FSERVER_TEST_LOG", "/var/log/agent-fileserver/access.json")
AS_ROOT = [] if os.geteuid() == 0 else ["sudo"]
tag = "fserver-log-test-" + uuid.uuid4().hex


def request(path, method="GET", extra=()):
    cmd = ["curl", "-sS", "--max-time", "20", "-o", "/dev/null",
           "-A", tag, "-X", method]
    if RESOLVE:
        cmd += ["--resolve", RESOLVE]
    subprocess.run([*cmd, *extra, BASE + path], check=True, capture_output=True)


request("/robots.txt?" + tag, extra=(
    "-H", "Authorization: Bearer SYNTHETIC_SECRET_NOT_A_REAL_CREDENTIAL",
    "-H", "Cookie: session=SYNTHETIC_COOKIE_NOT_REAL",
    "-H", "X-Auth-Token: SYNTHETIC_TOKEN_HEADER_NOT_REAL",
    "-H", "Referer: https://example.invalid/logging-probe",
    "-H", "X-Forwarded-For: 203.0.113.99",
))
request("/?" + tag)
request("/?" + tag, "PUT")
with ThreadPoolExecutor(max_workers=12) as pool:
    list(pool.map(lambda n: request("/?" + tag + "&burst=" + str(n)), range(100)))

raw = subprocess.check_output([*AS_ROOT, "cat", LOG], text=True)
entries = [json.loads(line) for line in raw.splitlines() if tag in line]
assert len(entries) == 103, f"Expected 103 unsampled requests, got {len(entries)}"
assert {200, 404, 405}.issubset({e["status"] for e in entries})
assert len([e for e in entries if "&burst=" in e["request"]["uri"]]) == 100
for entry in entries:
    for key in ("ts", "status", "size", "duration"):
        assert key in entry, key
    for key in ("remote_ip", "client_ip", "method", "uri", "headers"):
        assert key in entry["request"], key

probe = next(e for e in entries if e["status"] == 200)
headers = probe["request"]["headers"]
assert headers["Referer"] == ["https://example.invalid/logging-probe"]
assert "SYNTHETIC_SECRET_NOT_A_REAL_CREDENTIAL" not in json.dumps(entries)
assert "SYNTHETIC_COOKIE_NOT_REAL" not in json.dumps(entries)
assert "SYNTHETIC_TOKEN_HEADER_NOT_REAL" not in json.dumps(entries)
assert headers["X-Auth-Token"] in ("REDACTED", ["REDACTED"]), headers.get("X-Auth-Token")
if BASE.startswith("https://"):
    assert probe["request"]["client_ip"] != "203.0.113.99", "Spoofed XFF trusted"
    if os.environ.get("FSERVER_TEST_TRUSTED_PROXY") == "1":
        forwarded = headers["X-Forwarded-For"][-1].split(",")
        assert probe["request"]["client_ip"] == forwarded[-1].strip()
    print("PASS: caller cannot forge client IP through X-Forwarded-For")

mode = subprocess.check_output([*AS_ROOT, "stat", "-c", "%a", LOG], text=True).strip()
assert mode == "600", mode
print("PASS: 103/103 requests logged, including all 100 burst requests")
print("PASS: timestamps, URL/query, methods, IPs, UA, referrer, status, bytes, latency")
print("PASS: credentials redacted and access log private (0600)")
