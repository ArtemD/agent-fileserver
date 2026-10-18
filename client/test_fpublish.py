"""Offline client tests: no credentials or remote/server files are touched."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from unittest import mock

import fpublish as f

TOKEN = "R" * 22
SECRET = "A" * 43
URL = "https://example.invalid"
HEADERS = {
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "public, max-age=3600",
    "Content-Type": "application/octet-stream",
}


class Response:
    def __init__(self, status=200, data=b"", headers=None):
        self.status = status
        self.body = io.BytesIO(data)
        self.headers = headers or {}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, n=-1):
        return self.body.read(n)


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    @contextlib.contextmanager
    def request(self, method, path, headers=None, body=None):
        content = body.read() if body else None
        self.calls.append((method, path, dict(headers or {}), content))
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        yield result


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def pack(self, path):
        out = io.BytesIO()
        single, files = f.package(str(path), out)
        out.seek(0)
        archive = tarfile.open(fileobj=out)
        self.addCleanup(archive.close)
        return single, files, archive

    def test_file_exact_name_bytes_and_empty(self):
        for name, data in [('quoted "a\'b.txt', b"\x00binary\xff"), ("empty.txt", b"")]:
            path = self.root / name
            path.write_bytes(data)
            single, files, archive = self.pack(path)
            self.assertTrue(single)
            self.assertEqual(archive.getnames(), [name])
            self.assertEqual(archive.extractfile(name).read(), data)
            self.assertEqual(files[0]["sha256"], hashlib.sha256(data).hexdigest())

    def test_directory_trailing_slash_dot_and_mac_metadata(self):
        source = self.root / "dist"
        source.mkdir()
        (source / "known file.txt").write_bytes(b"hello")
        (source / ".DS_Store").write_bytes(b"omit")
        (source / "._file").write_bytes(b"omit")
        (source / "Icon\r").write_bytes(b"omit")
        (source / "__MACOSX").mkdir()
        (source / "__MACOSX" / ".metadata").write_bytes(b"omit")
        old = os.getcwd()
        try:
            os.chdir(source)
            for path in (".", "./", str(source) + "/"):
                single, files, archive = self.pack(path)
                self.assertFalse(single)
                self.assertEqual(archive.getnames(), ["dist", "dist/known file.txt"])
                self.assertEqual(files[0]["path"], "known file.txt")
        finally:
            os.chdir(old)
        self.assertEqual((source / ".DS_Store").read_bytes(), b"omit")

    def test_reject_dotfiles_secrets_sources_sidecars(self):
        for name in (".env", "secretS.txt", "credentials.json", "id_ed25519",
                     "code.py", "private.key", "source.map", "bad\\name"):
            with self.subTest(name=name):
                source = self.root / name
                source.write_bytes(b"reject")
                with self.assertRaises(f.Failure):
                    self.pack(source)
        source = self.root / "sidecars"
        source.mkdir()
        (source / "index.html").write_text("hello")
        (source / "index.html.gz").write_bytes(b"sidecar")
        with self.assertRaises(f.Failure):
            self.pack(source)

    def test_symlink_source_ancestor_metadata_root_and_special(self):
        target = self.root / "dist"
        target.mkdir()
        (target / "file.txt").write_bytes(b"test")
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        for path in (link, link / "file.txt", str(link) + "/../dist/file.txt", "/"):
            with self.subTest(path=path), self.assertRaises(f.Failure):
                self.pack(path)
        (target / ".DS_Store").symlink_to(target / "file.txt")
        with self.assertRaises(f.Failure):
            self.pack(target)
        if hasattr(os, "mkfifo"):
            fifo = self.root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaises(f.Failure):
                self.pack(fifo)

    def test_empty_folder_rejected(self):
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(f.Failure):
            self.pack(empty)

    def test_control_newline_names_refused_without_modifying_source(self):
        for name in ("new\nline.txt", "return\rname.txt", "tab\tname.txt", "control\x7f.txt"):
            source = self.root / name
            source.write_bytes(b"original")
            with self.assertRaisesRegex(f.Failure, "CR/LF or control"):
                self.pack(source)
            self.assertEqual(source.read_bytes(), b"original")


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def view(self, name=None, protected=False):
        return {"token": TOKEN, "url": URL + "/" + TOKEN + "/" +
                (f.urllib.parse.quote(name) if name else ""), "protected": protected}

    def test_streaming_retry_identical_multipart_and_bearer_separation(self):
        source = self.root / 'new "file.txt'
        source.write_bytes(b"exact public bytes")
        view = self.view(source.name)
        fake = FakeTransport([
            Response(503), Response(201, json.dumps(view).encode()),
            Response(404), Response(404), Response(200, source.read_bytes(), HEADERS),
        ])
        client = f.Client(URL, SECRET, fake, sleep=lambda _: None)
        result = client.publish(source, label='quoted " label')
        self.assertEqual(result["verified_url"], view["url"])
        first, second = fake.calls[:2]
        self.assertEqual(first, second)
        self.assertEqual(first[2]["Authorization"], "Bearer " + SECRET)
        self.assertRegex(first[2]["Idempotency-Key"], r"^[A-Za-z0-9_-]{16,128}$")
        self.assertLess(first[3].index(b'name="metadata"'), first[3].index(b'name="artifact"'))
        for method, path, headers, body in fake.calls[2:]:
            self.assertNotIn("Authorization", headers)
            self.assertEqual(method, "GET")
        self.assertIn("%22", fake.calls[-1][1])

    def test_protected_public_get_basic_only_and_unauth_401(self):
        source = self.root / "empty.txt"
        source.write_bytes(b"")
        headers = dict(HEADERS, **{"Cache-Control": "private, no-store"})
        fake = FakeTransport([
            Response(201, json.dumps(self.view(source.name, True)).encode()),
            Response(404), Response(404), Response(401), Response(200, b"", headers),
        ])
        f.Client(URL, SECRET, fake).publish(source, password="test password")
        self.assertNotIn("Authorization", fake.calls[-2][2])
        self.assertTrue(fake.calls[-1][2]["Authorization"].startswith("Basic "))
        self.assertNotIn(SECRET, fake.calls[-1][2]["Authorization"])

    def test_go_pathescape_metacharacters_preserve_returned_url(self):
        for filename, escaped in [
            ("a+b&c=d@e:$ document.txt", "a+b&c=d@e:$%20document.txt"),
            ("report #1 ? 50% + résumé.pdf", "report%20%231%20%3F%2050%25%20+%20r%C3%A9sum%C3%A9.pdf"),
        ]:
            source = self.root / filename
            source.write_bytes(b"punctuation")
            view = self.view(source.name)
            view["url"] = URL + "/" + TOKEN + "/" + escaped
            fake = FakeTransport([
                Response(201, json.dumps(view).encode()), Response(404),
                Response(404), Response(200, b"punctuation", HEADERS),
            ])
            result = f.Client(URL, SECRET, fake).publish(source)
            self.assertEqual(result["verified_url"], view["url"])
            self.assertIn("%2B", fake.calls[-1][1])

    def test_indexless_known_file_and_no_automatic_delete_on_failure(self):
        source = self.root / "dist"
        source.mkdir()
        (source / "data.txt").write_bytes(b"data")
        fake = FakeTransport([
            Response(201, json.dumps(self.view()).encode()),
            Response(404), Response(404), Response(404), Response(200, b"data", HEADERS),
        ])
        result = f.Client(URL, SECRET, fake).publish(source)
        self.assertEqual(result["verified_url"], URL + "/" + TOKEN + "/data.txt")
        fake = FakeTransport([
            Response(201, json.dumps(self.view()).encode()),
            Response(404), Response(404), Response(404), Response(200, b"WRONG", HEADERS),
        ])
        with self.assertRaises(f.Failure) as e:
            f.Client(URL, SECRET, fake).publish(source)
        self.assertEqual(e.exception.code, 5)
        self.assertNotIn("DELETE", [call[0] for call in fake.calls])

    def test_pivoted_manifest_url_never_requested(self):
        source = self.root / "file.txt"
        source.write_bytes(b"safe")
        view = self.view(source.name)
        view["url"] = "https://attacker.invalid/" + TOKEN + "/file.txt"
        fake = FakeTransport([Response(201, json.dumps(view).encode())])
        with self.assertRaises(f.Failure):
            f.Client(URL, SECRET, fake).publish(source)
        self.assertEqual(len(fake.calls), 1)

    def test_download_explicit_exclusive_and_no_response_filename(self):
        destination = self.root / "output.tar.gz"
        fake = FakeTransport([Response(200, b"download", {"Content-Disposition": "../../evil"})])
        result = f.Client(URL, SECRET, fake).download(TOKEN, destination)
        self.assertTrue(result["downloaded"])
        self.assertEqual(destination.read_bytes(), b"download")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            f.Client(URL, SECRET, fake).download(TOKEN, destination)
        self.assertEqual(len(fake.calls), 1)

    def test_secret_output_0600_and_never_overwrite(self):
        secret = self.root / "fresh-secret.json"
        with f.secret_destination(secret) as out:
            json.dump({"password": "fixture"}, out)
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            with f.secret_destination(secret):
                self.fail("overwrote secret")

    def test_config_fileguard_environment_and_schema(self):
        config = self.root / "config.json"
        config.write_text(json.dumps({"url": URL, "token": SECRET}))
        config.chmod(0o600)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(f.credentials(str(config)), (URL, SECRET))
            config.chmod(0o644)
            with self.assertRaises(f.Failure):
                f.credentials(str(config))
            config.chmod(0o600)
            (self.root / ".git").mkdir()
            with self.assertRaises(f.Failure):
                f.credentials(str(config))
        with mock.patch.dict(os.environ, {"FSERVER_URL": URL, "FSERVER_TOKEN": SECRET}, clear=True):
            self.assertEqual(f.credentials(), (URL, SECRET))

    def test_password_env_stdin_not_argv(self):
        args = f.parser().parse_args(["password", "set", TOKEN, "--password-stdin"])
        with mock.patch("sys.stdin", io.StringIO("private fixture\n")):
            self.assertEqual(f.password_value(args), "private fixture")
        for password in ("short", "x" * 73, "password\nbad"):
            with mock.patch.dict(os.environ, {"FSERVER_PASSWORD": password}):
                with self.assertRaises(f.Failure):
                    f.password_value(f.parser().parse_args(["password", "set", TOKEN]))

    def test_cli_password_reset_secret_only_in_private_file_and_other_commands(self):
        fresh = self.root / "fresh.json"
        view = self.view(protected=True)
        client = mock.Mock()
        client.release_path.return_value = "/_api/v1/releases/" + TOKEN
        client.api.return_value = {"username": "viewer", "password": "fresh private fixture",
                                   "release": view}
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(f, "credentials", return_value=(URL, SECRET)), \
                mock.patch.object(f, "Client", return_value=client), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(f.main(["password", "reset", TOKEN, "--secret-output", str(fresh)]), 0)
        self.assertEqual(json.loads(stdout.getvalue()), view)
        self.assertNotIn("fresh private fixture", stdout.getvalue() + stderr.getvalue())
        self.assertEqual(json.loads(fresh.read_text())["password"], "fresh private fixture")
        for args, method, suffix in [
            (["list"], "GET", ""),
            (["info", TOKEN], "GET", ""),
            (["delete", TOKEN], "DELETE", ""),
            (["password", "remove", TOKEN], "DELETE", "/password"),
            (["password", "set", TOKEN], "PUT", "/password"),
        ]:
            client.reset_mock()
            client.api.return_value = view
            with mock.patch.object(f, "credentials", return_value=(URL, SECRET)), \
                    mock.patch.object(f, "Client", return_value=client), \
                    mock.patch.dict(os.environ, {"FSERVER_PASSWORD": "fixture password"}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(f.main(args), 0)
            self.assertEqual(client.api.call_args[0][0], method)
            self.assertTrue(client.api.call_args[0][1].endswith(suffix))

    def test_verification_headers_and_protected_unauth_fail_closed(self):
        source = self.root / "file.txt"
        source.write_bytes(b"hello")
        files = [{"path": source.name, "size": 5, "sha256": hashlib.sha256(b"hello").hexdigest()}]
        for headers in ({}, dict(HEADERS, **{"Cache-Control": "private, no-store"})):
            fake = FakeTransport([Response(404), Response(404), Response(200, b"hello", headers)])
            with self.assertRaises(f.Failure) as e:
                f.Client(URL, SECRET, fake).verify(self.view(source.name), True, files, "")
            self.assertEqual(e.exception.code, 5)
        fake = FakeTransport([Response(404), Response(404), Response(200, b"hello", HEADERS)])
        with self.assertRaises(f.Failure) as e:
            f.Client(URL, SECRET, fake).verify(self.view(source.name, True), True, files, "fixture password")
        self.assertEqual(e.exception.code, 5)
        self.assertNotIn("Authorization", fake.calls[-1][2])

    def test_network_retry_same_bytes_and_no_retry_nontransient(self):
        source = self.root / "file.txt"
        source.write_bytes(b"test")
        fake = FakeTransport([OSError("network"), Response(401)])
        with self.assertRaises(f.Failure) as e:
            f.Client(URL, SECRET, fake, sleep=lambda _: None).publish(source)
        self.assertEqual(e.exception.code, 4)
        self.assertEqual(fake.calls[0], fake.calls[1])

    def test_invalid_origin_and_targets(self):
        for url in ("http://example.invalid", "https://user:secret@example.invalid",
                    "https://example.invalid/path", "https://example.invalid?x",
                    "https://example.invalid/#x", "https://example.invalid\\evil",
                    "https://example.invalid?", "https://example.invalid#"):
            with self.subTest(url=url), self.assertRaises(f.Failure):
                f.origin(url)
        c = f.Client(URL, SECRET, FakeTransport([]))
        with self.assertRaises(f.Failure):
            c.api("GET", "//attacker.invalid/path")
        for token in ("../secret", TOKEN + "/password", "short"):
            with self.assertRaises(f.Failure):
                c.release_path(token)


class PublicConfigTests(unittest.TestCase):
    def test_no_personal_default_and_missing_origin_error_is_sanitized(self):
        for environment in ({}, {"FSERVER_TOKEN": SECRET}, {"FSERVER_URL": "", "FSERVER_TOKEN": SECRET}):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(f.Failure) as error:
                    f.credentials()
                self.assertEqual(error.exception.code, 2)
                self.assertIn("FSERVER_URL", str(error.exception))
                self.assertNotIn(SECRET, str(error.exception))
        with mock.patch.dict(os.environ, {"FSERVER_URL": "https://user:private@example.invalid",
                                          "FSERVER_TOKEN": SECRET}, clear=True):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(f.main(["list"]), 2)
            self.assertNotIn("private", output.getvalue())
            self.assertNotIn(SECRET, output.getvalue())

    def test_config_url_required_overrides_and_skills_guard(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            config = root / "config.json"
            config.write_text(json.dumps({"token": SECRET}))
            config.chmod(0o600)
            with self.assertRaisesRegex(f.Failure, "FSERVER_URL"):
                f.credentials(config)
            os.environ["FSERVER_URL"] = URL
            self.assertEqual(f.credentials(config), (URL, SECRET))
            config.write_text(json.dumps({"url": "https://other.invalid", "token": SECRET}))
            self.assertEqual(f.credentials(config), (URL, SECRET))
            os.environ.pop("FSERVER_URL")
            self.assertEqual(f.credentials(config), ("https://other.invalid", SECRET))
            (root / "SKILL.md").write_text("fixture")
            with self.assertRaisesRegex(f.Failure, "outside repositories and skills"):
                f.credentials(config)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def zip(self, entries, compression=zipfile.ZIP_STORED):
        out = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(out, "w", compression=compression) as z:
                for name, value in entries:
                    z.writestr(name, value)
        return out.getvalue()

    def tar(self, entries, compressed=False):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz" if compressed else "w") as tar:
            for name, value in entries:
                info = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
        return out.getvalue()

    def inspect(self, data):
        return f.inspect_archive(io.BytesIO(data))

    def write(self, data):
        source = self.root / "website.zip"
        source.write_bytes(data)
        return source

    def view(self, filename=""):
        return {"token": TOKEN, "url": URL + "/" + TOKEN + "/" + filename, "protected": False}

    def test_zip_flat_wrapper_single_file_and_unwrap_only_once(self):
        for entries, single, expected in [
            ([("index.html", b"home"), ("assets/a.txt", b"asset")], False,
             ["assets/a.txt", "index.html"]),
            ([("site/index.html", b"home"), ("site/assets/a.txt", b"asset")], False,
             ["assets/a.txt", "index.html"]),
            ([("site/nested/index.html", b"home")], False, ["nested/index.html"]),
            ([("download.txt", b"file")], True, ["download.txt"]),
            ([("site/index.html", b"home"), ("empty/", b"")], False, ["site/index.html"]),
        ]:
            with self.subTest(entries=entries):
                actual_single, files = self.inspect(self.zip(entries))
                self.assertEqual(actual_single, single)
                self.assertEqual([item["path"] for item in files], expected)
                for item in files:
                    self.assertRegex(item["sha256"], "^[a-f0-9]{64}$")

    def test_tar_and_targz_keep_one_root_contract(self):
        for compressed in (False, True):
            for entries, single, expected in [
                ([("site/index.html", b"home"), ("site/assets/a.txt", b"asset")], False,
                 ["assets/a.txt", "index.html"]),
                ([("readme.txt", b"one")], True, ["readme.txt"]),
            ]:
                with self.subTest(compressed=compressed, entries=entries):
                    result_single, files = self.inspect(self.tar(entries, compressed))
                    self.assertEqual(result_single, single)
                    self.assertEqual([item["path"] for item in files], expected)
            with self.assertRaisesRegex(f.Failure, "exactly one root"):
                self.inspect(self.tar([("index.html", b"home"), ("other.txt", b"other")], compressed))

    def test_zip_mac_metadata_excluded_before_root_selection(self):
        data = self.zip([
            ("site/index.html", b"home"), (".DS_Store", b"metadata"),
            ("__MACOSX/", b""), ("__MACOSX/site/", b""),
            ("__MACOSX/site/._index.html", b"appledouble"), ("site/Icon\r", b"metadata"),
        ])
        single, files = self.inspect(data)
        self.assertFalse(single)
        self.assertEqual([item["path"] for item in files], ["index.html"])
        with self.assertRaises(f.Failure):
            self.inspect(self.zip([("site/index.html", b"home"), ("__MACOSX/secrets.txt", b"secret")]))
        for name in ("__MACOSX/bad\n/", "site/._bad\n", "__MACOSX/._bad\n"):
            with self.subTest(name=name), self.assertRaises(f.Failure):
                self.inspect(self.zip([("site/index.html", b"home"), (name, b"")]))

    def test_raw_zip_exact_bytes_same_idempotency_retry_and_every_file_verified(self):
        data = self.zip([("site/index.html", b"home"), ("site/asset.txt", b"asset")],
                        zipfile.ZIP_DEFLATED)
        source = self.write(data)
        fake = FakeTransport([
            Response(503), Response(201, json.dumps(self.view()).encode()),
            Response(404), Response(404), Response(200, b"home", HEADERS),
            Response(200, b"asset", HEADERS), Response(200, b"home", HEADERS),
        ])
        result = f.Client(URL, SECRET, fake, sleep=lambda _: None).publish(source, unpack_archive=True)
        self.assertEqual(result["verified_url"], self.view()["url"])
        self.assertEqual(fake.calls[0], fake.calls[1])
        multipart = fake.calls[0][3]
        payload = multipart.split(b"Content-Type: application/octet-stream\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        self.assertEqual(payload, data)
        self.assertEqual(source.read_bytes(), data)
        self.assertTrue(any(call[1].endswith("/asset.txt") for call in fake.calls))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["website.zip"])
        for call in fake.calls[2:]:
            self.assertNotIn("Authorization", call[2])

    def test_non_root_file_byte_mismatch_is_not_reported_verified_or_deleted(self):
        source = self.write(self.zip([("index.html", b"home"), ("a.txt", b"asset")]))
        fake = FakeTransport([
            Response(201, json.dumps(self.view()).encode()),
            Response(404), Response(404), Response(200, b"home", HEADERS),
            Response(200, b"WRONG", HEADERS),
        ])
        with self.assertRaises(f.Failure) as error:
            f.Client(URL, SECRET, fake).publish(source, unpack_archive=True)
        self.assertEqual(error.exception.code, 5)
        self.assertNotIn("DELETE", [call[0] for call in fake.calls])

    def test_raw_tar_and_targz_publish_original_bytes_not_a_second_wrapper(self):
        for compressed in (False, True):
            data = self.tar([("report.txt", b"report")], compressed)
            source = self.write(data)
            fake = FakeTransport([
                Response(201, json.dumps(self.view("report.txt")).encode()),
                Response(404), Response(404), Response(200, b"report", HEADERS),
            ])
            f.Client(URL, SECRET, fake).publish(source, unpack_archive=True)
            payload = fake.calls[0][3].split(b"Content-Type: application/octet-stream\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
            self.assertEqual(payload, data)

    def test_old_zip_publish_still_downloadable_file_not_unpacked(self):
        data = self.zip([("index.html", b"website")])
        source = self.write(data)
        fake = FakeTransport([
            Response(201, json.dumps(self.view(source.name)).encode()),
            Response(404), Response(404), Response(200, data, HEADERS),
        ])
        f.Client(URL, SECRET, fake).publish(source)
        payload = fake.calls[0][3].split(b"Content-Type: application/x-tar\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
            self.assertEqual(tar.getnames(), ["website.zip"])
            self.assertEqual(tar.extractfile("website.zip").read(), data)
        self.assertTrue(fake.calls[-1][1].endswith("/website.zip"))

    def test_cli_archive_flag_is_explicit(self):
        self.assertFalse(f.parser().parse_args(["publish", "file.zip"]).unpack_archive)
        self.assertTrue(f.parser().parse_args(["publish", "--unpack-archive", "file.zip"]).unpack_archive)
        client = mock.Mock()
        client.publish.return_value = self.view()
        with mock.patch.object(f, "credentials", return_value=(URL, SECRET)), \
                mock.patch.object(f, "Client", return_value=client), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(f.main(["publish", "--unpack-archive", "file.zip"]), 0)
        self.assertTrue(client.publish.call_args.kwargs["unpack_archive"])

    def test_zip_rejects_traversal_secrets_sources_conflicts_sidecars_and_controls(self):
        cases = [
            [("../escape", b"x")], [("/absolute", b"x")], [("C:\\escape", b"x")],
            [("site/../escape", b"x")], [("site//file", b"x")], [("site/./file", b"x")],
            [("site/.env", b"x")], [("site/secrets.json", b"x")], [("site/code.py", b"x")],
            [("site/key.pem", b"x")], [("site/node_modules/a.txt", b"x")],
            [("bad\nname", b"x")], [("bad\x7fname", b"x")],
            [("a", b"x"), ("a/b", b"y")], [("a/b", b"x"), ("a", b"y")],
            [("a", b"x"), ("a", b"y")], [("site/index.html", b"x"), ("site/index.html.gz", b"y")],
            [("/".join(["a"] * 33), b"x")], [("x" * 1025, b"x")],
        ]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(f.Failure):
                self.inspect(self.zip(entries))

    def test_zip_and_tar_links_specials_and_omitted_symlinks_rejected_before_http(self):
        for name in ("site/link", "site/.DS_Store"):
            for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (kind | 0o777) << 16
                source = self.write(self.zip([(info, b"target")]))
                fake = FakeTransport([])
                with self.subTest(name=name, kind=kind), self.assertRaises(f.Failure):
                    f.Client(URL, SECRET, fake).publish(source, unpack_archive=True)
                self.assertEqual(fake.calls, [])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            info = tarfile.TarInfo("site/link")
            info.type, info.linkname = kind, "target"
            with self.subTest(kind=kind), self.assertRaises(f.Failure):
                self.inspect(self.tar([(info, b"")]))

    def test_corrupt_zip_tar_gzip_and_unsupported_zip_methods_fail_safely(self):
        zipped = self.zip([("a.txt", b"unique payload")])
        corrupt = zipped.replace(b"unique payload", b"WRONG! payload", 1)
        gzip_data = bytearray(self.tar([("site/a.txt", b"data")], compressed=True))
        gzip_data[-8] ^= 1
        for data in (corrupt, zipped[:-20], b"not an archive", bytes(gzip_data),
                     self.zip([("a.txt", b"data")], zipfile.ZIP_BZIP2)):
            with self.subTest(data=data[:20]), self.assertRaises(f.Failure):
                self.inspect(data)

    def test_payload_and_entry_expansion_limits_apply_locally(self):
        for data in (self.zip([("a.txt", b"x" * 20)], zipfile.ZIP_DEFLATED),
                     self.tar([("site/a.txt", b"x" * 20)], compressed=True)):
            with mock.patch.object(f, "MAX_BYTES", 10), self.assertRaises(f.Failure):
                self.inspect(data)
        for data in (self.zip([("site/a.txt", b"x"), ("site/b.txt", b"y")]),
                     self.tar([("site/a.txt", b"x"), ("site/b.txt", b"y")])):
            with mock.patch.object(f, "MAX_ENTRIES", 2), self.assertRaises(f.Failure):
                self.inspect(data)
        with mock.patch.object(f, "MAX_BYTES", 10), self.assertRaises(f.Failure):
            f.raw_archive(self.write(b"x" * 11), io.BytesIO())

    def test_zip_central_admission_does_not_trust_declared_entry_count(self):
        data = bytearray(self.zip([("a.txt", b"a"), ("b.txt", b"b")]))
        end = data.rfind(b"PK\x05\x06")
        f.struct.pack_into("<2H", data, end + 8, 1, 1)
        with mock.patch.object(f.zipfile, "ZipFile") as parsed, self.assertRaises(f.Failure):
            self.inspect(bytes(data))
        parsed.assert_not_called()
        # Admission must not mistake a ZIP comment signature for an end record.
        # ZipFile itself may conservatively refuse this unusual legal comment.
        data = bytearray(self.zip([("a.txt", b"a")]))
        comment = b"comment PK\x05\x06 not a record"
        f.struct.pack_into("<H", data, len(data) - 2, len(comment))
        f.zip_entry_budget(io.BytesIO(bytes(data) + comment))

    def test_zip_utf8_names_with_or_without_explicit_utf8_flag(self):
        for flagged in (False, True):
            data = bytearray(self.zip([("site/résumé.txt", b"utf8")]))
            if not flagged:
                for offset, position in ((6, data.find(b"PK\x03\x04")), (8, data.find(b"PK\x01\x02"))):
                    f.struct.pack_into("<H", data, position + offset, 0)
            single, files = self.inspect(bytes(data))
            self.assertFalse(single)
            self.assertEqual(files[0]["path"], "résumé.txt")

    def test_zip_encrypted_flags_unix_link_extensions_and_non_metadata_dotunderscore(self):
        for flags, extra in [(1, b""), (0x40, b""), (0, f.struct.pack("<2H", 0x756e, 0)),
                             (0, f.struct.pack("<2H", 0x000d, 0))]:
            info = zipfile.ZipInfo("a.txt")
            info.extra = extra
            data = bytearray(self.zip([(info, b"a")]))
            if flags:
                local, central = data.find(b"PK\x03\x04"), data.find(b"PK\x01\x02")
                f.struct.pack_into("<H", data, local + 6, flags)
                f.struct.pack_into("<H", data, central + 8, flags)
            with self.subTest(flags=flags, extra=extra), self.assertRaises(f.Failure):
                self.inspect(bytes(data))
        for entries in ([("._", b"not metadata")], [(".DS_Store/", b"")],
                        [("a:b.txt", b"colon")]):
            with self.subTest(entries=entries), self.assertRaises(f.Failure):
                self.inspect(self.zip(entries))

    def test_tar_dangerous_paths_secrets_sidecars_duplicates_and_sparse_pax(self):
        cases = [
            [("../outside", b"x")], [("site/.env", b"x")], [("site/code.sh", b"x")],
            [("site/.DS_Store", b"x")], [("site\\file", b"x")],
            [("site/a", b"x"), ("site/a", b"y")],
            [("site/a", b"x"), ("site/a.gz", b"y")],
        ]
        info = tarfile.TarInfo("site/a")
        info.pax_headers = {"SCHILY.realsize": "1"}
        cases.append([(info, b"x")])
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(f.Failure):
                self.inspect(self.tar(entries))

    def test_archive_source_no_links_specials_or_directory_and_bounded_snapshot(self):
        source = self.write(self.zip([("a.txt", b"x" * (f.CHUNK * 3))]))
        original = f.open_source

        class BoundedSource:
            def __init__(self, path):
                self.stream = original(path)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, n=-1):
                self_outer.assertGreater(n, 0)
                self_outer.assertLessEqual(n, f.CHUNK)
                return self.stream.read(n)

        self_outer = self
        with mock.patch.object(f, "open_source", BoundedSource):
            single, files = f.raw_archive(source, io.BytesIO())
        self.assertTrue(single)
        self.assertEqual(files[0]["size"], f.CHUNK * 3)
        link = self.root / "linked.zip"
        link.symlink_to(source)
        for path in (link, self.root):
            with self.subTest(path=path), self.assertRaises(f.Failure):
                f.raw_archive(path, io.BytesIO())
        if hasattr(os, "mkfifo"):
            fifo = self.root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaises(f.Failure):
                f.raw_archive(fifo, io.BytesIO())

    def test_archive_mutation_during_snapshot_rejected_before_upload(self):
        source = self.write(self.zip([("a.txt", b"original")]))
        original = f.open_source

        class ChangingSource:
            def __init__(self, path):
                self.stream, self.changed = original(path), False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, n):
                data = self.stream.read(n)
                if not self.changed:
                    self.changed = True
                    before = source.stat()
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                return data

        fake = FakeTransport([])
        with mock.patch.object(f, "open_source", ChangingSource), self.assertRaisesRegex(f.Failure, "changed"):
            f.Client(URL, SECRET, fake).publish(source, unpack_archive=True)
        self.assertEqual(fake.calls, [])


class TransportTests(unittest.TestCase):
    def setUp(self):
        # Test environment semantics without inherited VM/OS proxy settings.
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        proxies = mock.patch.object(f.urllib.request, "getproxies",
                                    f.urllib.request.getproxies_environment)
        bypass = mock.patch.object(f.urllib.request, "proxy_bypass",
                                   f.urllib.request.proxy_bypass_environment)
        proxies.start()
        bypass.start()
        self.addCleanup(proxies.stop)
        self.addCleanup(bypass.stop)

    def test_https_normal_validation_redirect_refused_and_bounded_upload(self):
        class Connection:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs
                self.sent = []
                connections.append(self)

            def putrequest(self, *args, **kwargs):
                self.request = args

            def putheader(self, *args):
                pass

            def endheaders(self):
                pass

            def send(self, data):
                self.sent.append(len(data))

            def getresponse(self):
                return Response(302, headers={"Location": "https://attacker.invalid/"})

            def close(self):
                pass

        connections = []
        with mock.patch.object(f.http.client, "HTTPSConnection", Connection):
            t = f.Transport(URL)
            with self.assertRaises(f.Failure):
                with t.request("POST", "/_api/v1/releases",
                               {"Authorization": "Bearer " + SECRET}, io.BytesIO(b"x" * (f.CHUNK * 3))):
                    self.fail("followed redirect")
        self.assertEqual(len(connections), 1)
        self.assertLessEqual(max(connections[0].sent), f.CHUNK)
        context = connections[0].kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, f.ssl.CERT_REQUIRED)

    def test_connect_proxy_separates_auth_and_verifies_original_tls_hostname(self):
        class Socket:
            def __init__(self, response):
                self.response, self.sent = response, []

            def setsockopt(self, *args):
                pass

            def sendall(self, data):
                self.sent.append(bytes(data))

            def makefile(self, mode, *args):
                return io.BytesIO(self.response)

            def close(self):
                pass

        raw = Socket(b"HTTP/1.1 200 Connection established\r\n\r\n")
        tls = Socket(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        os.environ["HTTPS_PROXY"] = "http://proxy-user:proxy%3Apass@proxy.invalid:8080"
        transport = f.Transport(URL)
        with mock.patch.object(f.http.client.socket, "create_connection", return_value=raw) as connect, \
                mock.patch.object(transport.context, "wrap_socket", return_value=tls) as wrap:
            with transport.request("POST", "/_api/v1/releases",
                                   {"Authorization": "Bearer " + SECRET},
                                   io.BytesIO(b"x" * (f.CHUNK * 2 + 1))) as response:
                self.assertEqual(response.status, 204)
        self.assertEqual(connect.call_args[0][0], ("proxy.invalid", 8080))
        self.assertEqual(wrap.call_args[0][0], raw)
        self.assertEqual(wrap.call_args[1]["server_hostname"], "example.invalid")
        self.assertTrue(transport.context.check_hostname)
        self.assertEqual(transport.context.verify_mode, f.ssl.CERT_REQUIRED)
        plaintext, encrypted = b"".join(raw.sent), b"".join(tls.sent)
        proxy_auth = b"Basic " + f.base64.b64encode(b"proxy-user:proxy:pass")
        self.assertIn(b"CONNECT example.invalid:443 ", plaintext)
        self.assertIn(b"Proxy-Authorization: " + proxy_auth, plaintext)
        self.assertNotIn(SECRET.encode(), plaintext)
        self.assertNotIn(b"\r\nAuthorization:", plaintext)
        self.assertIn(b"Authorization: Bearer " + SECRET.encode(), encrypted)
        self.assertIn(b"Host: example.invalid\r\n", encrypted)
        self.assertNotIn(b"Proxy-Authorization", encrypted)
        self.assertNotIn(proxy_auth, encrypted)
        self.assertLessEqual(max(map(len, tls.sent)), f.CHUNK)

    def test_no_proxy_bypasses_proxy_for_host_domain_and_port(self):
        for bypass, server in [("example.invalid", URL), (".invalid", URL),
                               ("example.invalid:8443", URL + ":8443"), ("*", URL)]:
            with self.subTest(bypass=bypass), mock.patch.dict(
                    os.environ, {"HTTPS_PROXY": "http://proxy.invalid:8080", "NO_PROXY": bypass}):
                with mock.patch.object(f.http.client, "HTTPSConnection") as connection:
                    f.Transport(server).connection()
                parsed = f.urllib.parse.urlsplit(server)
                self.assertEqual(connection.call_args[0], (parsed.hostname, parsed.port))
                connection.return_value.set_tunnel.assert_not_called()

    def test_lowercase_schemeless_proxy_default_port_and_no_origin_auth(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://unused.invalid:123",
                                         "https_proxy": "proxy.invalid:8080"}):
            with mock.patch.object(f.http.client, "HTTPSConnection") as connection:
                f.Transport(URL + ":8443").connection()
            self.assertEqual(connection.call_args[0], ("proxy.invalid", 8080))
            connection.return_value.set_tunnel.assert_called_once_with(
                "example.invalid", 8443, headers={})
        os.environ["https_proxy"] = "http://proxy.invalid"
        with mock.patch.object(f.http.client, "HTTPSConnection") as connection:
            f.Transport(URL).connection()
        self.assertEqual(connection.call_args[0], ("proxy.invalid", 80))

    def test_proxy_unsupported_schemes_and_malformed_settings_refuse_without_secrets(self):
        for proxy in (
                "https://user:private-proxy-password@proxy.invalid:443",
                "socks5://user:private-proxy-password@proxy.invalid:1080",
                "http://proxy.invalid/path", "http://proxy.invalid?query",
                "http://proxy.invalid#", "http://proxy.invalid:0",
                "http://proxy.invalid:65536", "http://proxy.invalid:notaport",
                "http://proxy.invalid\\evil", "http://proxy.invalid\r\nHeader:inject",
                "http://user%0A:private-proxy-password@proxy.invalid",
                "http://user%3Aevil:private-proxy-password@proxy.invalid",
                "http://user%ZZ:private-proxy-password@proxy.invalid"):
            with self.subTest(proxy=proxy), mock.patch.dict(os.environ, {"HTTPS_PROXY": proxy}):
                with mock.patch.object(f.http.client, "HTTPSConnection") as connection:
                    with self.assertRaises(f.Failure) as error:
                        f.Transport(URL).connection()
                connection.assert_not_called()
                self.assertNotIn("private-proxy-password", str(error.exception))
                self.assertEqual(error.exception.code, 2)
                if proxy.startswith(("https:", "socks5:")):
                    self.assertIn("unsupported", str(error.exception))


if __name__ == "__main__":
    unittest.main()
