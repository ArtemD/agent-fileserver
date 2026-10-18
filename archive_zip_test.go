package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type zipFixture struct {
	name, body string
	mode       os.FileMode
	method     uint16
	extra      []byte
}

func fixtureZIP(t *testing.T, files ...zipFixture) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: f.method, Extra: f.extra}
		h.SetMode(f.mode)
		dst, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(dst, f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipFile(name, body string) zipFixture {
	return zipFixture{name: name, body: body, mode: 0644, method: zip.Deflate}
}

func zipDir(name string) zipFixture {
	return zipFixture{name: name, mode: os.ModeDir | 0755}
}

func unzipTest(t *testing.T, b []byte, cfg apiConfig) (string, string, error) {
	t.Helper()
	dst := t.TempDir()
	root, err := extractArtifact(context.Background(), bytes.NewReader(b), dst, cfg)
	return root, dst, err
}

func mutateZIP(b []byte, edit func(local, central, end []byte)) []byte {
	b = bytes.Clone(b)
	c := bytes.Index(b, []byte("PK\x01\x02"))
	e := bytes.LastIndex(b, []byte("PK\x05\x06"))
	local := int(binary.LittleEndian.Uint32(b[c+42:]))
	edit(b[local:c], b[c:e], b[e:])
	return b
}

func TestZIPNormalization(t *testing.T) {
	cases := []struct {
		name, root string
		files      []zipFixture
		single     bool
		index      bool
	}{
		{"flat", ".", []zipFixture{zipFile("index.html", "hi"), zipFile("assets/x.css", "body{}")}, false, true},
		{"flat-files", ".", []zipFixture{zipFile("a.txt", "a"), zipFile("b.txt", "b")}, false, false},
		{"wrapped", "site", []zipFixture{zipDir("site/"), zipFile("site/index.html", "hi"), zipFile("site/css/x.css", "x")}, false, true},
		{"implicit-wrapper", "site", []zipFixture{zipFile("site/index.html", "hi")}, false, true},
		{"late-wrapper", "site", []zipFixture{zipFile("site/index.html", "hi"), zipDir("site/")}, false, true},
		{"unwrap-once", "outer", []zipFixture{zipFile("outer/inner/index.html", "hi")}, false, false},
		{"one-file", "report.txt", []zipFixture{zipFile("report.txt", "hi")}, true, false},
		{"one-index", "index.html", []zipFixture{zipFile("index.html", "hi")}, true, false},
		{"two-wrappers", ".", []zipFixture{zipFile("a/x", "x"), zipFile("b/y", "y")}, false, false},
		{"empty-dirs-with-file", ".", []zipFixture{zipDir("empty/"), zipFile("x.txt", "")}, false, false},
		{"unicode", "café", []zipFixture{zipFile("café/日本.txt", "ok")}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dst, err := unzipTest(t, fixtureZIP(t, tc.files...), archiveTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join(dst, tc.root); root != want {
				t.Fatalf("root %q, want %q", root, want)
			}
			plan, err := inspectSource(root)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.root.Close()
			if plan.single != tc.single || plan.hasIndex != tc.index {
				t.Fatalf("single=%v index=%v", plan.single, plan.hasIndex)
			}
			for _, f := range tc.files {
				st, err := os.Lstat(filepath.Join(dst, f.name))
				if err != nil {
					t.Fatal(err)
				}
				if st.IsDir() {
					if st.Mode().Perm() != 0700 {
						t.Fatal(st.Mode())
					}
				} else {
					body, err := os.ReadFile(filepath.Join(dst, f.name))
					if err != nil || string(body) != f.body || st.Mode().Perm() != 0600 {
						t.Fatalf("bad extraction %q: %q %v %v", f.name, body, st.Mode(), err)
					}
				}
			}
		})
	}
}

func TestZIPMacMetadata(t *testing.T) {
	files := []zipFixture{
		zipFile("site/index.html", "hi"), zipFile(".DS_Store", "finder"),
		zipFile("site/.DS_Store", "finder"), zipFile("site/._index.html", "appledouble"),
		zipFile("site/Icon\r", "icon"), zipDir("__MACOSX/"),
		zipDir("__MACOSX/site/"), zipFile("__MACOSX/site/._index.html", "appledouble"),
	}
	root, dst, err := unzipTest(t, fixtureZIP(t, files...), archiveTestConfig())
	if err != nil || root != filepath.Join(dst, "site") {
		t.Fatalf("%s %v", root, err)
	}
	for _, f := range files[1:] {
		if _, err := os.Lstat(filepath.Join(dst, f.name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("metadata extracted: %q %v", f.name, err)
		}
	}
	s := testStore(t)
	m, _, err := s.publish(root, "zip", true)
	if err != nil || m.Files != 1 || !m.SPA {
		t.Fatalf("shared publish: %+v %v", m, err)
	}
}

func TestZIPUnsafePaths(t *testing.T) {
	names := []string{"../x", "/x", "a/../x", "a/./x", "a//x", "./x", "a\\x", "\\\\host\\file",
		"C:/x", "C:x", "a:b", "a\x00x", "a\rx", "a\nx", "a\tx", "a\x7fx", "a\x85x",
		"a/\xff", "a//", "", "a/" + strings.Repeat("x", 1024), strings.Repeat("a/", 32) + "x"}
	for _, name := range names {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			f := zipFile(name, "evil")
			if strings.HasSuffix(name, "/") {
				f = zipDir(name)
			}
			if _, _, err := unzipTest(t, fixtureZIP(t, f), archiveTestConfig()); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
}

func TestZIPDuplicatesConflictsAndTypes(t *testing.T) {
	cases := map[string][]zipFixture{
		"duplicate-file": {zipFile("a", ""), zipFile("a", "")},
		"duplicate-dir":  {zipDir("a/"), zipDir("a/"), zipFile("a/x", "")},
		"file-parent":    {zipFile("a", ""), zipFile("a/x", "")},
		"parent-file":    {zipFile("a/x", ""), zipFile("a", "")},
		"dir-file":       {zipDir("a/"), zipFile("a", "")},
		"file-dir":       {zipFile("a", ""), zipDir("a/")},
		"metadata-dup":   {zipFile("index.html", ""), zipFile(".DS_Store", ""), zipFile(".DS_Store", "")},
		"metadata-link":  {zipFile("index.html", ""), {name: ".DS_Store", mode: os.ModeSymlink | 0777}},
		"symlink":        {{name: "link", body: "/etc/passwd", mode: os.ModeSymlink | 0777}},
		"symlink-dir":    {{name: "link/", mode: os.ModeSymlink | 0777}, zipFile("index.html", "")},
		"fifo":           {{name: "fifo", mode: os.ModeNamedPipe | 0600}},
		"char":           {{name: "char", mode: os.ModeDevice | os.ModeCharDevice | 0600}},
		"block":          {{name: "block", mode: os.ModeDevice | 0600}},
		"socket":         {{name: "sock", mode: os.ModeSocket | 0600}},
		"unix-link":      {{name: "a", extra: []byte{0x0d, 0, 0, 0}}},
		"asi-link":       {{name: "a", extra: []byte{0x6e, 0x75, 0, 0}}},
		"zip64-extra":    {{name: "a", extra: []byte{1, 0, 0, 0}}},
		"aes-extra":      {{name: "a", extra: []byte{1, 0x99, 0, 0}}},
		"strong-extra":   {{name: "a", extra: []byte{0x17, 0, 0, 0}}},
		"bad-extra":      {{name: "a", extra: []byte{0x42}}},
		"unknown-mac":    {zipFile("index.html", ""), zipFile("__MACOSX/.env", "secret")},
		"mac-root-file":  {zipFile("index.html", ""), zipFile("__MACOSX", "unknown")},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := unzipTest(t, fixtureZIP(t, files...), archiveTestConfig()); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestZIPEmptyAndDirectories(t *testing.T) {
	for name, files := range map[string][]zipFixture{
		"empty": nil, "directory": {zipDir("site/")}, "directories": {zipDir("a/"), zipDir("b/")},
		"implicit": {zipDir("a/b/")}, "metadata": {zipFile(".DS_Store", "")},
		"mac-tree": {zipDir("__MACOSX/"), zipFile("__MACOSX/._a", "")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := unzipTest(t, fixtureZIP(t, files...), archiveTestConfig()); !errors.Is(err, errUnsafeArchive) {
				t.Fatalf("empty/directory-only ZIP: %v", err)
			}
		})
	}
	// Keep existing tar semantics, even though ZIP directory-only is rejected.
	for _, gz := range []bool{false, true} {
		b := fixtureTar(t, tarFixture{name: "site/", typ: tar.TypeDir})
		if gz {
			b = fixtureGzip(t, b)
		}
		if _, _, err := unzipTest(t, b, archiveTestConfig()); err != nil {
			t.Fatalf("tar directory regression: %v", err)
		}
	}
}

func TestZIPMalformed(t *testing.T) {
	good := fixtureZIP(t, zipFile("index.html", "hello"))
	patch := func(edit func(local, central, end []byte)) []byte { return mutateZIP(good, edit) }
	cases := map[string][]byte{
		"magic-only": []byte("PK\x03\x04"), "truncated": good[:len(good)-1],
		"trailing": append(bytes.Clone(good), 0), "prefix": append([]byte("PK\x03\x04junk"), good...),
		"encrypted":           patch(func(l, c, e []byte) { l[6] |= 1; c[8] |= 1 }),
		"strong-encryption":   patch(func(l, c, e []byte) { l[6] |= 64; c[8] |= 64 }),
		"unsupported-method":  patch(func(l, c, e []byte) { l[8] = 99; c[10] = 99 }),
		"local-method":        patch(func(l, c, e []byte) { l[8] = 0 }),
		"local-flags":         patch(func(l, c, e []byte) { l[6] = 0 }),
		"local-name":          patch(func(l, c, e []byte) { l[30] = 'z' }),
		"local-signature":     patch(func(l, c, e []byte) { l[0] = 'X' }),
		"local-offset":        patch(func(l, c, e []byte) { c[42] = 1 }),
		"central-crc":         patch(func(l, c, e []byte) { c[16] ^= 1 }),
		"payload":             patch(func(l, c, e []byte) { l[40] ^= 0xff }),
		"descriptor-crc":      patch(func(l, c, e []byte) { l[len(l)-12] ^= 1 }),
		"descriptor-length":   patch(func(l, c, e []byte) { l[len(l)-4] ^= 1 }),
		"advertised-bomb":     patch(func(l, c, e []byte) { zipLE.PutUint32(c[24:], 0xffffffff) }),
		"false-small-size":    patch(func(l, c, e []byte) { zipLE.PutUint32(c[24:], 1); zipLE.PutUint32(l[len(l)-4:], 1) }),
		"multidisk":           patch(func(l, c, e []byte) { e[4] = 1 }),
		"split-entry":         patch(func(l, c, e []byte) { c[34] = 1 }),
		"count-mismatch":      patch(func(l, c, e []byte) { e[8] = 0; e[10] = 0 }),
		"count-wrap":          patch(func(l, c, e []byte) { e[8] = 0xff; e[9] = 0xff; e[10] = 0xff; e[11] = 0xff }),
		"directory-offset":    patch(func(l, c, e []byte) { e[16] ^= 1 }),
		"directory-size":      patch(func(l, c, e []byte) { e[12] ^= 1 }),
		"directory-signature": patch(func(l, c, e []byte) { c[0] = 'x' }),
		"unknown-creator":     patch(func(l, c, e []byte) { c[5] = 255 }),
		"unix-unknown-type":   patch(func(l, c, e []byte) { c[41] = 0xe0 }),
		"windows-reparse": patch(func(l, c, e []byte) {
			c[5] = 10
			zipLE.PutUint32(c[38:], 0x400)
		}),
		"windows-device": patch(func(l, c, e []byte) {
			c[5] = 0
			zipLE.PutUint32(c[38:], 0x40)
		}),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := unzipTest(t, b, archiveTestConfig()); err == nil {
				t.Fatal("malformed ZIP accepted")
			}
		})
	}
	// Exercise every truncation boundary, including local data, data descriptor,
	// central directory, EOCD and comments.
	for n := 0; n < len(good); n++ {
		if _, _, err := unzipTest(t, good[:n], archiveTestConfig()); err == nil {
			t.Fatalf("truncation accepted at %d/%d", n, len(good))
		}
	}
}

func rawZIP(t *testing.T, body string, crc uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "a.txt", Method: zip.Store, CRC32: crc,
		CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body))}
	dst, err := w.CreateRaw(h)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(dst, body)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestZIPStoredAndZeroCRC(t *testing.T) {
	for _, body := range []string{"hello", ""} {
		if _, _, err := unzipTest(t, rawZIP(t, body, crc32.ChecksumIEEE([]byte(body))), archiveTestConfig()); err != nil {
			t.Fatal(err)
		}
	}
	// archive/zip does not verify a zero central CRC without a descriptor.
	if _, _, err := unzipTest(t, rawZIP(t, "hello", 0), archiveTestConfig()); err == nil {
		t.Fatal("zero CRC bypass")
	}
}

func TestZIPCommentsExtrasAndDirectoryPayload(t *testing.T) {
	extra := []byte{0x75, 0x78, 5, 0, 1, 1, 0, 1, 0} // Info-ZIP UID/GID, not links
	b := fixtureZIP(t, zipFixture{name: "a.txt", body: "hello", extra: extra})
	// Valid archive comments are bounded and do not become published content.
	e := bytes.LastIndex(b, []byte("PK\x05\x06"))
	zipLE.PutUint16(b[e+20:], 7)
	b = append(b, []byte("comment")...)
	if _, _, err := unzipTest(t, b, archiveTestConfig()); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", "bad"} {
		// Like some JAR writers, encode a directory as an empty deflate
		// stream rather than store/zero. Unlike File.Open's directory fast
		// path, ingestion still checks its stream and CRC.
		b := fixtureZIP(t, zipFile("d?", body), zipFile("index.html", "hi"))
		b = mutateZIP(b, func(l, c, e []byte) {
			l[31] = '/'
			c[47] = '/'
		})
		_, _, err := unzipTest(t, b, archiveTestConfig())
		if body == "" && err != nil || body != "" && err == nil {
			t.Fatalf("directory body=%q: %v", body, err)
		}
	}
}

func TestZIPUnconsumedCompressedBytes(t *testing.T) {
	for name, junk := range map[string][]byte{
		"padding": {0},
		"hidden-local-entry": func() []byte {
			b := rawZIP(t, "hidden", crc32.ChecksumIEEE([]byte("hidden")))
			return b[:bytes.Index(b, []byte("PK\x01\x02"))]
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			b := fixtureZIP(t, zipFile("index.html", "hi"))
			central := bytes.Index(b, []byte("PK\x01\x02"))
			payloadEnd := central - 16 // signed data descriptor
			patched := append([]byte{}, b[:payloadEnd]...)
			patched = append(patched, junk...)
			patched = append(patched, b[payloadEnd:]...)
			c := central + len(junk)
			compressed := zipLE.Uint32(patched[c+20:]) + uint32(len(junk))
			zipLE.PutUint32(patched[c+20:], compressed)
			zipLE.PutUint32(patched[payloadEnd+len(junk)+8:], compressed)
			e := bytes.LastIndex(patched, []byte("PK\x05\x06"))
			zipLE.PutUint32(patched[e+16:], uint32(c))
			if _, _, err := unzipTest(t, patched, archiveTestConfig()); err == nil {
				t.Fatal("accepted unread bytes inside compressed extent")
			}
		})
	}
}

func TestZIPLimits(t *testing.T) {
	t.Run("payload", func(t *testing.T) {
		cfg := archiveTestConfig()
		cfg.MaxExtractBytes = 4
		for _, files := range [][]zipFixture{
			{zipFile("x", "hello")}, {zipFile("x", "abc"), zipFile("y", "de")},
			{zipFile("x", ""), zipFile(".DS_Store", "hello")},
			{zipFile("x", strings.Repeat("0", 2<<20))},
		} {
			if _, _, err := unzipTest(t, fixtureZIP(t, files...), cfg); !errors.Is(err, errArchiveLimit) {
				t.Fatalf("payload budget: %v", err)
			}
		}
	})
	t.Run("objects", func(t *testing.T) {
		cfg := archiveTestConfig()
		cfg.MaxEntries = 2
		for _, files := range [][]zipFixture{
			{zipFile("a/b/c", "")}, {zipFile("a/x", ""), zipFile("a/y", "")},
			{zipFile("x", ""), zipFile("__MACOSX/nested/._x", "")},
			{zipFile("a", ""), zipFile("b", ""), zipFile("c", "")},
		} {
			if _, _, err := unzipTest(t, fixtureZIP(t, files...), cfg); !errors.Is(err, errArchiveLimit) {
				t.Fatalf("entry/implicit budget: %v", err)
			}
		}
		cfg.MaxEntries = 3
		if _, _, err := unzipTest(t, fixtureZIP(t, zipFile("a/x", ""), zipDir("a/"), zipFile("a/y", "")), cfg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("central-count-lies", func(t *testing.T) {
		b := fixtureZIP(t, zipFile("a", ""), zipFile("b", ""), zipFile("c", ""))
		e := bytes.LastIndex(b, []byte("PK\x05\x06"))
		zipLE.PutUint16(b[e+8:], 1)
		zipLE.PutUint16(b[e+10:], 1)
		cfg := archiveTestConfig()
		cfg.MaxEntries = 2
		if _, _, err := unzipTest(t, b, cfg); !errors.Is(err, errArchiveLimit) {
			t.Fatalf("preallocation guard: %v", err)
		}
	})
	t.Run("wire", func(t *testing.T) {
		b := fixtureZIP(t, zipFile("x", "hello"))
		for _, file := range []bool{false, true} {
			for _, delta := range []int64{-1, 0, 1} {
				cfg := archiveTestConfig()
				cfg.MaxUploadBytes = int64(len(b)) + delta
				var r io.Reader = bytes.NewReader(b)
				if file {
					f, err := os.CreateTemp(t.TempDir(), "input")
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					f.Write(b)
					f.Seek(0, io.SeekStart)
					r = f
				}
				_, err := extractArtifact(context.Background(), r, t.TempDir(), cfg)
				if delta < 0 && !errors.Is(err, errArchiveLimit) || delta >= 0 && err != nil {
					t.Fatalf("file=%v delta=%d: %v", file, delta, err)
				}
			}
		}
	})
}

func TestZIPMetadataCRCAndSecrets(t *testing.T) {
	for _, name := range []string{".DS_Store", "._index.html", "Icon\r", "__MACOSX/._index.html"} {
		t.Run(fmt.Sprintf("crc-%q", name), func(t *testing.T) {
			b := fixtureZIP(t, zipFile(name, "metadata"), zipFile("index.html", "hi"))
			b = mutateZIP(b, func(l, c, e []byte) { l[30+len(name)] ^= 0xff })
			if _, _, err := unzipTest(t, b, archiveTestConfig()); err == nil {
				t.Fatal("omitted metadata skipped CRC")
			}
		})
	}
	for _, name := range []string{".env", ".ENV.production", ".git/config", "credentials.json", "secrets/x.txt",
		"private.key", "index.php", "app.js.map", "._/secret.txt", ".DS_Store/x.txt", "Icon\r/x.txt"} {
		t.Run(fmt.Sprintf("secret-%q", name), func(t *testing.T) {
			root, _, err := unzipTest(t, fixtureZIP(t, zipFile("index.html", "hi"), zipFile(name, "secret")), archiveTestConfig())
			if err != nil {
				return
			}
			if p, err := inspectSource(root); err == nil {
				p.root.Close()
				t.Fatal("ZIP bypassed shared publisher validation")
			}
		})
	}
}

func TestZIPSpoolReuseAndCleanup(t *testing.T) {
	b := fixtureZIP(t, zipFile("a.txt", "hello"))
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	if err := os.Mkdir(dst, 0700); err != nil {
		t.Fatal(err)
	}
	// A nonzero initial offset must be honored. A non-writable spool parent
	// demonstrates that existing file input needs no second disk copy.
	path := filepath.Join(parent, "input")
	if err := os.WriteFile(path, append([]byte("prefix"), b...), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Seek(6, io.SeekStart)
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	if _, err := extractArtifact(context.Background(), f, dst, archiveTestConfig()); err != nil {
		t.Fatal(err)
	}
	if off, err := f.Seek(0, io.SeekCurrent); err != nil || off != 6 {
		t.Fatalf("ReaderAt extraction moved file offset: %d %v", off, err)
	}
	for _, bad := range []bool{false, true} {
		dir := t.TempDir()
		out := filepath.Join(dir, "out")
		os.Mkdir(out, 0700)
		input := b
		if bad {
			input = b[:len(b)-1]
		}
		_, err := extractArtifact(context.Background(), bytes.NewBuffer(input), out, archiveTestConfig())
		if bad != (err != nil) {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "out" {
			t.Fatalf("fallback spool leak: %v %v", entries, err)
		}
	}
}

func TestArchiveWireLimitAllFormats(t *testing.T) {
	tarBytes := fixtureTar(t, tarFixture{name: "site/x", body: "hello"})
	for name, b := range map[string][]byte{
		"tar": tarBytes, "tar.gz": fixtureGzip(t, tarBytes), "zip": fixtureZIP(t, zipFile("site/x", "hello")),
	} {
		t.Run(name, func(t *testing.T) {
			for _, delta := range []int64{-1, 0, 1} {
				cfg := archiveTestConfig()
				cfg.MaxUploadBytes = int64(len(b)) + delta
				_, _, err := unzipTest(t, b, cfg)
				if delta < 0 && !errors.Is(err, errArchiveLimit) || delta >= 0 && err != nil {
					t.Fatalf("delta=%d: %v", delta, err)
				}
			}
		})
	}
}

func TestZIPCancellationAndExistingLinks(t *testing.T) {
	b := fixtureZIP(t, zipFile("assets/x.txt", "hello"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := extractArtifact(ctx, bytes.NewReader(b), t.TempDir(), archiveTestConfig()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	dst := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dst, "assets")); err != nil {
		t.Fatal(err)
	}
	if _, err := extractArtifact(context.Background(), bytes.NewReader(b), dst, archiveTestConfig()); err == nil {
		t.Fatal("preexisting symlink accepted")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("followed preexisting link", entries, err)
	}
}
