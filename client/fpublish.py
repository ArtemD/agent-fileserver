#!/usr/bin/env python3
"""Owner-approved HTTPS static publishing. Python 3 standard library only."""
import argparse
import base64
import contextlib
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import struct
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import zlib

CHUNK = 128 * 1024
MAX_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 5000
TOKEN = re.compile(r"[A-Za-z0-9_-]{22}\Z")
TRANSIENT = {408, 429, 502, 503, 504}
FORBIDDEN_EXT = {
    ".map", ".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore",
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml",
    ".pht", ".phar", ".cgi", ".fcgi", ".pl", ".pm", ".py", ".pyc",
    ".pyo", ".rb", ".sh", ".bash", ".zsh", ".ps1",
}


class Failure(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


def no_symlinks(path):
    """Inspect unnormalized components too: symlink/../file is not permitted."""
    raw = os.fspath(path)
    current = Path(os.path.sep) if os.path.isabs(raw) else Path.cwd()
    for part in raw.split(os.path.sep):
        if part in ("", "."):
            continue
        current = current / part
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode):
            raise Failure("symlinks (including ancestors) are forbidden", 2)
    return Path(os.path.abspath(raw))


def origin(url):
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        raise Failure("invalid HTTPS server URL", 2)
    if (u.scheme != "https" or not u.hostname or u.username is not None
            or u.password is not None or u.path not in ("", "/")
            or u.query or u.fragment or any(c in url for c in ("\\", "?", "#"))
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)):
        raise Failure("server URL must be an HTTPS origin without credentials/path/query", 2)
    if port is not None and not 1 <= port <= 65535:
        raise Failure("invalid server port", 2)
    return urllib.parse.urlunsplit(("https", u.netloc, "", "", ""))


def credentials(config=None):
    data = {}
    path = config or os.environ.get("FSERVER_CONFIG")
    if path:
        p = no_symlinks(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(p, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            st = os.fstat(f.fileno())
            if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600
                    or (hasattr(os, "getuid") and st.st_uid != os.getuid())
                    or st.st_nlink != 1 or st.st_size > 16384):
                raise Failure("config must be an owner-owned, single-link regular 0600 file", 2)
            # Do not read credentials from a checkout, even an unrelated repo.
            if any((parent / ".git").exists() or (parent / "SKILL.md").exists()
                   for parent in p.parents):
                raise Failure("credential config must be outside repositories and skills", 2)
            data = json.load(f)
        if (not isinstance(data, dict) or set(data) - {"url", "token"}
                or any(not isinstance(v, str) for v in data.values())):
            raise Failure("config schema is {\"url\": HTTPS_ORIGIN, \"token\": SECRET}", 2)
    configured_url = os.environ.get("FSERVER_URL", data.get("url", ""))
    if not configured_url:
        raise Failure("set FSERVER_URL to your HTTPS server origin, or set url in an external 0600 config", 2)
    url = origin(configured_url)
    token = os.environ.get("FSERVER_TOKEN", data.get("token", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,256}", token):
        raise Failure("set FSERVER_TOKEN or use an external 0600 config", 2)
    return url, token


class Transport:
    def __init__(self, url):
        self.url = origin(url)
        self.parsed = urllib.parse.urlsplit(self.url)
        self.context = ssl.create_default_context()

    def connection(self):
        # HTTPSConnection performs CONNECT first, then verifies TLS against its
        # tunnel destination. Origin Authorization is sent only inside that TLS.
        proxy = urllib.request.getproxies().get("https")
        if not proxy or urllib.request.proxy_bypass(self.parsed.netloc):
            return http.client.HTTPSConnection(self.parsed.hostname, self.parsed.port,
                                               context=self.context, timeout=180)
        try:
            if (any(ord(c) <= 32 or ord(c) == 127 for c in proxy)
                    or any(c in proxy for c in ("\\", "?", "#"))):
                raise ValueError()
            parsed = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
            if parsed.scheme != "http":
                raise Failure("unsupported HTTPS proxy scheme; only HTTP CONNECT proxies are supported", 2)
            port = parsed.port if parsed.port is not None else 80
            if (not parsed.hostname or "%" in parsed.hostname
                    or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                    or not 1 <= port <= 65535):
                raise ValueError()
            tunnel_headers = {}
            if parsed.username is not None:
                if any(re.search(r"%(?![0-9A-Fa-f]{2})", part)
                       for part in (parsed.username, parsed.password or "")):
                    raise ValueError()
                username = urllib.parse.unquote(parsed.username, encoding="utf-8", errors="strict")
                password = urllib.parse.unquote(parsed.password or "", encoding="utf-8", errors="strict")
                if ":" in username or any(ord(c) < 32 or 127 <= ord(c) <= 159
                                          for c in username + password):
                    raise ValueError()
                raw = (username + ":" + password).encode("utf-8")
                tunnel_headers["Proxy-Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        except (ValueError, UnicodeError, TypeError):
            raise Failure("invalid HTTPS proxy configuration", 2)
        c = http.client.HTTPSConnection(parsed.hostname, port, context=self.context, timeout=180)
        c.set_tunnel(self.parsed.hostname, self.parsed.port or 443, headers=tunnel_headers)
        return c

    @contextlib.contextmanager
    def request(self, method, path, headers=None, body=None):
        # Only origin-form targets constructed locally, never URLs from responses.
        if (not path.startswith("/") or path.startswith("//") or "\\" in path
                or "#" in path or "?" in path
                or any(ord(c) <= 32 or ord(c) == 127 for c in path)):
            raise Failure("refusing unsafe HTTP target", 2)
        c = self.connection()
        try:
            c.putrequest(method, path, skip_accept_encoding=True)
            for k, v in (headers or {}).items():
                c.putheader(k, v)
            c.putheader("Accept-Encoding", "identity")
            if body is not None:
                c.putheader("Content-Length", str(body.seek(0, os.SEEK_END)))
                body.seek(0)
            c.endheaders()
            if body is not None:
                while True:
                    chunk = body.read(CHUNK)
                    if not chunk:
                        break
                    c.send(chunk)
            response = c.getresponse()
            if 300 <= response.status < 400:
                raise Failure("redirect refused; credentials were not forwarded")
            yield response
        finally:
            c.close()


def read_json(response):
    raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise Failure("oversized API response")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure("invalid API JSON response")


def api_error(status):
    return Failure("API returned HTTP %d" % status, 4 if status in (401, 403) else 3)


def omitted(name):
    return name == ".DS_Store" or name.startswith("._") or name in ("Icon\r", "__MACOSX")


def validate_name(name, directory):
    lower = name.lower()
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name):
        raise Failure("filename contains CR/LF or control characters; prepare a safely named static copy", 2)
    if (not name or name in (".", "..") or "/" in name or "\\" in name
            or name.startswith(".") or (directory and lower == "node_modules")
            or lower.split(".", 1)[0] in ("credentials", "secrets")
            or lower in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
            or Path(lower).suffix in FORBIDDEN_EXT):
        raise Failure("unsafe source name; prepare a clean static output directory", 2)
    try:
        name.encode("utf-8", "strict")
    except UnicodeError:
        raise Failure("source names must be valid UTF-8", 2)


class HashReader:
    def __init__(self, f):
        self.f, self.digest = f, hashlib.sha256()

    def read(self, n=-1):
        chunk = self.f.read(n)
        self.digest.update(chunk)
        return chunk


def same_stat(a, b):
    return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns) == (
        b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns)


def open_source(path):
    """On POSIX, pin every ancestor directory so a race cannot pivot the read."""
    no_symlinks(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if (os.open in getattr(os, "supports_dir_fd", set())
            and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")):
        absolute = Path(os.path.abspath(path))
        directory = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in absolute.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                os.close(directory)
                directory = child
            return os.fdopen(os.open(absolute.name, flags, dir_fd=directory), "rb")
        finally:
            os.close(directory)
    # Platforms without dir_fd still reject static symlink paths and check
    # source identity before/after reads; don't grant concurrent workspace writers.
    return os.fdopen(os.open(path, flags), "rb")


def package(source, target):
    source = no_symlinks(source)
    if source == Path(source.anchor):
        raise Failure("publishing a filesystem root is forbidden", 2)
    initial = os.lstat(source)
    if not (stat.S_ISREG(initial.st_mode) or stat.S_ISDIR(initial.st_mode)):
        raise Failure("source must be a regular file or directory", 2)
    files, count, total = [], 0, 0
    single = stat.S_ISREG(initial.st_mode)

    with tarfile.open(fileobj=target, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        def add(path, rel):
            nonlocal count, total
            no_symlinks(path)
            st = os.lstat(path)
            directory = stat.S_ISDIR(st.st_mode)
            # Even omitted metadata cannot be a symlink or special file.
            if not (directory or stat.S_ISREG(st.st_mode)):
                raise Failure("symlinks and special files are forbidden", 2)
            if path.name != "Icon\r" and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path.name):
                raise Failure("filename contains CR/LF or control characters; prepare a safely named static copy", 2)
            if omitted(path.name):
                if rel == source.name:
                    raise Failure("source itself is omitted Mac metadata", 2)
                return
            validate_name(path.name, directory)
            count += 1
            total += 0 if directory else st.st_size
            if count > 5000 or total > 100 * 1024 * 1024:
                raise Failure("local artifact exceeds default upload limits", 2)
            if len(rel.encode("utf-8")) > 1024 or len(Path(rel).parts) > 32:
                raise Failure("source path exceeds archive limits", 2)
            info = tarfile.TarInfo(rel)
            info.mode, info.mtime = (0o755 if directory else 0o644), 0
            if directory:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                for child in sorted(path.iterdir(), key=lambda p: p.name):
                    add(child, rel + "/" + child.name)
                if not same_stat(st, os.lstat(path)):
                    raise Failure("source changed during packaging", 2)
            else:
                if path.suffix.lower() in (".br", ".gz") and path.with_suffix("").exists():
                    raise Failure("supplied compression sidecars are forbidden", 2)
                with open_source(path) as f:
                    opened = os.fstat(f.fileno())
                    if not stat.S_ISREG(opened.st_mode) or not same_stat(st, opened):
                        raise Failure("source changed during packaging", 2)
                    reader = HashReader(f)
                    info.size = st.st_size
                    archive.addfile(info, reader)
                    no_symlinks(path)
                    if not same_stat(st, os.fstat(f.fileno())) or not same_stat(st, os.lstat(path)):
                        raise Failure("source changed during packaging", 2)
                    files.append({"path": rel.split("/", 1)[1] if not single else path.name,
                                  "size": st.st_size, "sha256": reader.digest.hexdigest()})
        add(source, source.name)
    if not files:
        raise Failure("source contains no publishable files", 2)
    return single, files


class ArchiveBudget:
    """Bound decompressed tar headers/padding as well as member payloads."""
    def __init__(self, stream):
        self.stream = stream
        self.left = MAX_BYTES + MAX_ENTRIES * 2048 + 1048576

    def read(self, n=-1):
        data = self.stream.read(min(CHUNK, self.left + 1, n if n >= 0 else CHUNK))
        self.left -= len(data)
        if self.left < 0:
            raise Failure("archive exceeds default extraction limits", 2)
        return data


def zip_entry_budget(archive):
    """Admit actual central records before ZipFile allocates member objects.

    Like the server, exclude global ZIP64, split disks, prefixes and trailers;
    none is needed for 100 MiB / 5000 entries. Header reads are small and bounded.
    """
    size = archive.seek(0, os.SEEK_END)
    archive.seek(max(0, size - 65557))
    tail = archive.read(65557)
    end = tail.rfind(b"PK\x05\x06")
    while end >= 0 and (len(tail) - end < 22 or
                        end + 22 + struct.unpack_from("<H", tail, end + 20)[0] != len(tail)):
        end = tail.rfind(b"PK\x05\x06", 0, end)
    if end < 0:
        raise Failure("invalid ZIP directory", 2)
    disk, start_disk, on_disk, count, length, start, comment = struct.unpack_from("<4H2IH", tail, end + 4)
    stop = size - len(tail) + end
    if (disk or start_disk or on_disk != count or count == 65535
            or end + 22 + comment != len(tail) or start + length != stop):
        raise Failure("unsupported ZIP directory", 2)
    archive.seek(start)
    actual = 0
    while archive.tell() < stop:
        actual += 1
        if actual > MAX_ENTRIES or count > MAX_ENTRIES:
            raise Failure("archive exceeds default entry limit", 2)
        header = archive.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise Failure("invalid ZIP directory", 2)
        name, extra, comment = struct.unpack_from("<3H", header, 28)
        if name > 1024 or archive.seek(name + extra + comment, os.SEEK_CUR) > stop:
            raise Failure("invalid ZIP directory", 2)
    if actual != count:
        raise Failure("invalid ZIP entry count", 2)


def safe_zip_extra(extra):
    while extra:
        if len(extra) < 4:
            return False
        tag, size = struct.unpack_from("<2H", extra)
        if size > len(extra) - 4 or tag in (0x0001, 0x000d, 0x756e):
            return False  # ZIP64 or Unix extensions capable of encoding links.
        extra = extra[4 + size:]
    return True


def inspect_archive(archive):
    """Hash regular members without extraction; normalize exactly one wrapper.

    ZIP may have several roots (a site), while tar retains the API's one-root
    contract. Verification compares each original public file, never a repacked
    archive's bytes. Server-side archive validation remains authoritative.
    """
    seen, kept, files = {}, set(), []
    count = total = 0

    def member(name, directory, size, stream, mac=False):
        nonlocal count, total
        count += 1
        if count > MAX_ENTRIES or size < 0 or size > MAX_BYTES - total:
            raise Failure("archive exceeds default extraction limits", 2)
        total += size
        name = name[:-1] if directory and name.endswith("/") else name
        parts = name.split("/")
        if (not name or len(name.encode("utf-8")) > 1024 or len(parts) > 32
                or "\\" in name or any(p in ("", ".", "..") for p in parts)):
            raise Failure("unsafe archive member path", 2)
        # Only known harmless Mac leaves are omitted. Unknown __MACOSX files
        # are refused, not assumed harmless. All types are checked by callers.
        leaf = parts[-1]
        mac_leaf = leaf in (".DS_Store", "Icon\r") or (leaf.startswith("._") and len(leaf) > 2)
        metadata = mac and ((not directory and mac_leaf) or (directory and parts[0] == "__MACOSX"))
        if mac and ":" in name:
            raise Failure("unsafe ZIP member path", 2)
        if mac and parts[0] == "__MACOSX" and not directory and not mac_leaf:
            raise Failure("unknown Mac archive metadata; prepare a clean archive", 2)
        for i, part in enumerate(parts):
            mac_icon = mac and not directory and i == len(parts) - 1 and part == "Icon\r"
            if not mac_icon and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in part):
                raise Failure("archive member contains control characters", 2)
            if mac and (part == "__MACOSX" or (i == len(parts) - 1 and metadata)):
                continue
            validate_name(part, directory or i < len(parts) - 1)
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            if seen.get(parent) == "f":
                raise Failure("conflicting archive paths", 2)
            seen.setdefault(parent, "i")
        if name in seen and not (seen[name] == "i" and directory):
            raise Failure("duplicate or conflicting archive paths", 2)
        seen[name] = "d" if directory else "f"
        if len(seen) > MAX_ENTRIES:
            raise Failure("archive exceeds default entry limit", 2)
        if not metadata:
            kept.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        if directory:
            if size or (stream is not None and stream.read(1)):
                raise Failure("archive directory contains payload", 2)
            return
        digest, actual = hashlib.sha256(), 0
        while True:
            chunk = stream.read(min(CHUNK, size - actual + 1))
            if not chunk:
                break
            actual += len(chunk)
            if actual > size:
                raise Failure("archive member size mismatch", 2)
            digest.update(chunk)
        if actual != size:
            raise Failure("archive member size mismatch", 2)
        if not metadata:
            files.append({"path": name, "size": size, "sha256": digest.hexdigest()})

    archive.seek(0)
    magic = archive.read(4)
    archive.seek(0)
    zipped = magic.startswith(b"PK")
    try:
        if zipped:
            zip_entry_budget(archive)
            with zipfile.ZipFile(archive) as z:
                if len(z.infolist()) > MAX_ENTRIES:
                    raise Failure("archive exceeds default entry limit", 2)
                for info in z.infolist():
                    directory = info.is_dir()
                    kind = stat.S_IFMT(info.external_attr >> 16)
                    if (info.orig_filename != info.filename
                            or info.flag_bits & ~0x080e
                            or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            or not safe_zip_extra(info.extra)
                            or (info.compress_type == zipfile.ZIP_STORED and
                                (info.flag_bits & 6 or info.compress_size != info.file_size))
                            or kind not in (0, stat.S_IFDIR if directory else stat.S_IFREG)):
                        raise Failure("unsupported, linked, or unsafe ZIP member", 2)
                    # Go accepts valid UTF-8 names even when a ZIP producer
                    # forgot the UTF-8 flag; undo Python's CP437 fallback.
                    name = (info.filename if info.flag_bits & 0x800 else
                            info.filename.encode("cp437").decode("utf-8", "strict"))
                    with z.open(info) as stream:
                        member(name, directory, info.file_size, stream, mac=True)
        else:
            with contextlib.ExitStack() as stack:
                stream = stack.enter_context(gzip.GzipFile(fileobj=archive)) if magic[:2] == b"\x1f\x8b" else archive
                bounded = ArchiveBudget(stream)
                with tarfile.open(fileobj=bounded, mode="r|") as tar:
                    for info in tar:
                        if (info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                                or any("sparse" in k.lower() or k == "SCHILY.realsize" for k in info.pax_headers)):
                            raise Failure("links, special files, and sparse tar members are forbidden", 2)
                        if info.isdir():
                            member(info.name, True, info.size, None)
                        else:
                            with tar.extractfile(info) as content:
                                member(info.name, False, info.size, content)
                while bounded.read(CHUNK):
                    pass  # Verify gzip CRC and bound trailing padding/metadata.
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError, OSError, ValueError, UnicodeError, zlib.error):
        raise Failure("invalid or unsupported archive; prepare a clean ZIP, tar, or tar.gz", 2)
    if not files:
        raise Failure("archive contains no publishable files", 2)
    roots = {name.split("/", 1)[0] for name in kept}
    if not zipped and len(roots) != 1:
        raise Failure("tar archives must contain exactly one root file or directory", 2)
    single = len(roots) == 1 and seen[next(iter(roots))] == "f"
    unwrap = len(roots) == 1 and not single
    for file in files:
        name = file["path"]
        if Path(name).suffix.lower() in (".gz", ".br") and name.rsplit(".", 1)[0] in kept:
            raise Failure("supplied compression sidecars are forbidden", 2)
        if unwrap:
            file["path"] = name.split("/", 1)[1]
    return single, sorted(files, key=lambda item: item["path"])


def raw_archive(source, target):
    """Snapshot a regular source once; inspection and retries use only this copy."""
    path = no_symlinks(source)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
        raise Failure("--unpack-archive requires a regular archive within 100 MiB", 2)
    with open_source(path) as stream:
        if not same_stat(before, os.fstat(stream.fileno())):
            raise Failure("archive changed while reading", 2)
        size = 0
        while True:
            data = stream.read(CHUNK)
            if not data:
                break
            size += len(data)
            if size > MAX_BYTES:
                raise Failure("archive exceeds default upload limit", 2)
            target.write(data)
        no_symlinks(path)
        if (size != before.st_size or not same_stat(before, os.fstat(stream.fileno()))
                or not same_stat(before, os.lstat(path))):
            raise Failure("archive changed while reading", 2)
    return inspect_archive(target)


def password_value(args):
    if getattr(args, "password_stdin", False):
        value = sys.stdin.readline(1024)
        if value.endswith("\n"):
            value = value[:-1]
    else:
        value = os.environ.get("FSERVER_PASSWORD", "")
    if (not 8 <= len(value.encode("utf-8")) <= 72
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise Failure("password must be 8–72 UTF-8 bytes without controls; use FSERVER_PASSWORD or --password-stdin", 2)
    return value


def spool_json(value):
    f = tempfile.TemporaryFile()
    f.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    f.seek(0)
    return f


class Client:
    def __init__(self, url, token, transport=None, sleep=time.sleep):
        self.url, self.token = origin(url), token
        self.transport = transport or Transport(url)
        self.sleep = sleep

    def api(self, method, path, body=None, headers=None):
        if not path.startswith("/_api/v1/"):
            raise Failure("bearer credentials restricted to management routes", 2)
        h = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        h.update(headers or {})
        with self.transport.request(method, path, h, body) as r:
            if r.status not in (200, 201, 204):
                raise api_error(r.status)
            return None if r.status == 204 else read_json(r)

    def release_path(self, token):
        if not TOKEN.fullmatch(token):
            raise Failure("expected the exact release token; do not guess paths", 2)
        return "/_api/v1/releases/" + token

    def verify(self, view, single, files, password):
        if not isinstance(view, dict) or not TOKEN.fullmatch(view.get("token", "")):
            raise Failure("invalid release view", 5)
        root = "/" + view["token"] + "/"
        paths = {f["path"]: f for f in files}
        known = files[0]["path"] if single or "index.html" not in paths else "index.html"
        expected_path = root + (known if single else "")
        try:
            returned = view.get("url", "")
            parsed = urllib.parse.urlsplit(returned)
            valid_url = (
                urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) == self.url
                and not parsed.query and not parsed.fragment
                and "?" not in returned and "#" not in returned
                and not re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path)
                and not any(ord(c) <= 32 or ord(c) == 127 for c in returned)
                and urllib.parse.unquote(parsed.path, encoding="utf-8", errors="strict") == expected_path)
        except (ValueError, UnicodeError, TypeError):
            valid_url = False
        # Equivalent percent-escapes are allowed: Go PathEscape retains legal
        # path punctuation such as '+' and '&' that Python quote escapes.
        if not valid_url or view.get("protected", False) != bool(password):
            raise Failure("unexpected release URL/policy; release was NOT deleted", 5)
        public_headers = {}
        if password:
            raw = ("viewer:" + password).encode("utf-8")
            public_headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")

        def get(path, status=200, file=None, headers=None):
            with self.transport.request("GET", path, headers or {}) as r:
                if r.status != status:
                    raise Failure("public verification status mismatch; release was NOT deleted", 5)
                if status != 200:
                    return
                robots = r.getheader("X-Robots-Tag", "").lower()
                cache = r.getheader("Cache-Control", "").lower()
                if (not all(v in robots for v in ("noindex", "nofollow", "noarchive"))
                        or r.getheader("Referrer-Policy", "").lower() != "no-referrer"
                        or r.getheader("X-Content-Type-Options", "").lower() != "nosniff"
                        or not r.getheader("Content-Type")
                        or r.getheader("Content-Encoding", "identity") != "identity"
                        or (password and not ("private" in cache and "no-store" in cache))
                        or (not password and not ("public" in cache and "max-age=3600" in cache))):
                    raise Failure("public verification headers mismatch; release was NOT deleted", 5)
                digest, size = hashlib.sha256(), 0
                while True:
                    chunk = r.read(CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > file["size"]:
                        raise Failure("public bytes mismatch; release was NOT deleted", 5)
                    digest.update(chunk)
                if size != file["size"] or digest.hexdigest() != file["sha256"]:
                    raise Failure("public bytes mismatch; release was NOT deleted", 5)
        try:
            get("/", 404)
            get("/" + secrets.token_urlsafe(16) + "/", 404)
            if password:
                get(root if not single else root + urllib.parse.quote(known, safe="/"), 401)
            if not single:
                get(root, 200 if "index.html" in paths else 404,
                    paths.get("index.html"), public_headers)
            for f in files:
                get(root + urllib.parse.quote(f["path"], safe="/"),
                    file=f, headers=public_headers)
        except Failure:
            raise
        except (OSError, http.client.HTTPException):
            raise Failure("public verification network failure; release was NOT deleted", 5)
        view = dict(view)
        view["verified_url"] = (view["url"] if single or "index.html" in paths else
                                self.url + root + urllib.parse.quote(known, safe="/"))
        return view

    def publish(self, source, label="", spa=False, password="", unpack_archive=False):
        if len(label) > 200 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in label):
            raise Failure("label must be at most 200 characters without controls", 2)
        metadata = {"label": label, "spa": spa}
        if password:
            metadata["password"] = password
        # Disk-backed immutable request: retries reuse both key and exact bytes.
        with tempfile.TemporaryFile() as archive, tempfile.TemporaryFile() as request:
            single, files = raw_archive(source, archive) if unpack_archive else package(source, archive)
            artifact_name, artifact_type = (("artifact", "application/octet-stream") if unpack_archive
                                            else ("artifact.tar", "application/x-tar"))
            boundary = "fserver-" + secrets.token_hex(24)
            request.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"metadata\"\r\n"
                           "Content-Type: application/json\r\n\r\n").encode("ascii"))
            request.write(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            request.write(("\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"artifact\"; "
                           "filename=\"" + artifact_name + "\"\r\nContent-Type: " + artifact_type + "\r\n\r\n").encode("ascii"))
            archive.seek(0)
            while True:
                chunk = archive.read(CHUNK)
                if not chunk:
                    break
                request.write(chunk)
            request.write(("\r\n--" + boundary + "--\r\n").encode("ascii"))
            if request.tell() > 100 * 1024 * 1024 + 65536:
                raise Failure("archive exceeds default upload limit", 2)
            headers = {"Authorization": "Bearer " + self.token,
                       "Content-Type": "multipart/form-data; boundary=" + boundary,
                       "Idempotency-Key": secrets.token_urlsafe(24), "Accept": "application/json"}
            view = None
            for attempt in range(3):
                request.seek(0)
                try:
                    with self.transport.request("POST", "/_api/v1/releases", headers, request) as r:
                        if r.status == 201:
                            view = read_json(r)
                            break
                        if r.status not in TRANSIENT or attempt == 2:
                            raise api_error(r.status)
                        delay = r.getheader("Retry-After", "")
                        delay = min(int(delay), 30) if delay.isdigit() else 2 ** attempt
                except ssl.SSLCertVerificationError:
                    raise Failure("HTTPS certificate verification failed")
                except (OSError, http.client.HTTPException):
                    if attempt == 2:
                        raise Failure("upload network failure; outcome may be unknown; no release deleted")
                    delay = 2 ** attempt
                print("transient upload failure; retrying identical request", file=sys.stderr)
                self.sleep(delay)
            return self.verify(view, single, files, password)

    def download(self, token, destination):
        path = self.release_path(token) + "/download"
        dest = Path(destination)
        no_symlinks(dest.parent)
        # Explicit destination, exclusive creation; no filename from HTTP is trusted.
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                with self.transport.request("GET", path, {"Authorization": "Bearer " + self.token}) as r:
                    if r.status != 200:
                        raise api_error(r.status)
                    while True:
                        chunk = r.read(CHUNK)
                        if not chunk:
                            break
                        f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # A failed download remains explicitly named . No recursive cleanup.
            print("download failed; destination may be partial (not removed)", file=sys.stderr)
            raise
        return {"token": token, "downloaded": True}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", help="external owner-owned 0600 JSON file")
    sub = p.add_subparsers(dest="command", required=True)
    pub = sub.add_parser("publish")
    pub.add_argument("source")
    pub.add_argument("--label", default="")
    pub.add_argument("--spa", action="store_true")
    pub.add_argument("--unpack-archive", action="store_true",
                     help="publish ZIP/tar/tar.gz contents (one wrapper removed); verify every original file, not archive-byte identity")
    protection = pub.add_mutually_exclusive_group()
    protection.add_argument("--protected", action="store_true", help="password from FSERVER_PASSWORD")
    protection.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list")
    for command in ("info", "delete", "download"):
        item = sub.add_parser(command)
        item.add_argument("token")
        if command == "download":
            item.add_argument("--output", required=True, help="new destination file; never overwritten")
    pw = sub.add_parser("password")
    pwsub = pw.add_subparsers(dest="action", required=True)
    for action in ("set", "reset", "remove"):
        item = pwsub.add_parser(action)
        item.add_argument("token")
        if action == "set":
            item.add_argument("--password-stdin", action="store_true")
        if action == "reset":
            item.add_argument("--secret-output", required=True,
                              help="fresh password JSON in NEW external 0600 owner file, never stdout")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        url, token = credentials(args.config)
        c = Client(url, token)
        if args.command == "publish":
            password = password_value(args) if args.protected or args.password_stdin else ""
            result = c.publish(args.source, args.label, args.spa, password,
                               unpack_archive=args.unpack_archive)
        elif args.command == "list":
            result = c.api("GET", "/_api/v1/releases")
        elif args.command == "info":
            result = c.api("GET", c.release_path(args.token))
        elif args.command == "delete":
            c.api("DELETE", c.release_path(args.token))
            result = {"token": args.token, "deleted": True}
        elif args.command == "download":
            result = c.download(args.token, args.output)
        else:
            path = c.release_path(args.token) + "/password"
            if args.action == "set":
                with spool_json({"password": password_value(args)}) as body:
                    result = c.api("PUT", path, body, {"Content-Type": "application/json"})
            elif args.action == "remove":
                result = c.api("DELETE", path)
            else:
                # Reserve destination BEFORE reset to avoid losing a generated password.
                with secret_destination(args.secret_output) as output:
                    value = c.api("POST", path + "/reset")
                    if (not isinstance(value, dict) or not isinstance(value.get("password"), str)
                            or value.get("username") != "viewer"
                            or not isinstance(value.get("release"), dict)
                            or value["release"].get("token") != args.token):
                        raise Failure("invalid password reset response")
                    json.dump({"username": value.get("username"), "password": value["password"]}, output)
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                    result = value["release"]
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Failure as e:
        print("fpublish: " + str(e), file=sys.stderr)
        return e.code
    except (OSError, ValueError, UnicodeError, http.client.HTTPException):
        print("fpublish: local file, configuration, or HTTPS transport failure", file=sys.stderr)
        return 3


@contextlib.contextmanager
def secret_destination(path):
    no_symlinks(Path(path).parent)
    p = Path(os.path.abspath(path))
    if any((parent / ".git").exists() or (parent / "SKILL.md").exists() for parent in p.parents):
        raise Failure("secret output must be outside repositories and skills", 2)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yield f


if __name__ == "__main__":
    sys.exit(main())
