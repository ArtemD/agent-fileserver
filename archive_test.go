package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

type tarFixture struct {
	name string
	typ  byte
	body string
	pax  map[string]string
}

func fixtureTar(t *testing.T, files ...tarFixture) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Typeflag: typ, Mode: 0600, PAXRecords: f.pax}
		if typ == tar.TypeReg {
			h.Size = int64(len(f.body))
		}
		if typ == tar.TypeLink || typ == tar.TypeSymlink {
			h.Linkname = "elsewhere"
		}
		if e := w.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Size > 0 {
			if _, e := io.WriteString(w, f.body); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func fixtureGzip(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, e := z.Write(b); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func archiveTestConfig() apiConfig { return apiConfig{MaxExtractBytes: 1 << 20, MaxEntries: 100} }
func TestArchiveRootsAndImplicitParents(t *testing.T) {
	for _, gzipIt := range []bool{false, true} {
		for _, files := range [][]tarFixture{{{"report.txt", 0, "", nil}}, {{"site/nested/x.txt", 0, "hi", nil}, {"site/", tar.TypeDir, "", nil}}, {{"site/", tar.TypeDir, "", nil}}} {
			b := fixtureTar(t, files...)
			if gzipIt {
				b = fixtureGzip(t, b)
			}
			dir := t.TempDir()
			root, e := extractArtifact(context.Background(), bytes.NewReader(b), dir, archiveTestConfig())
			if e != nil {
				t.Fatal(e)
			}
			if filepath.Dir(root) != dir {
				t.Fatal(root)
			}
		}
	}
}
func TestArchiveUnsafeEntries(t *testing.T) {
	cases := map[string][]tarFixture{
		"traversal": {{"site/../evil", 0, "x", nil}}, "absolute": {{"/evil", 0, "", nil}}, "backslash": {{"site\\evil", 0, "", nil}}, "dot": {{"site/./x", 0, "", nil}}, "empty-component": {{"site//x", 0, "", nil}},
		"duplicate": {{"a/x", 0, "", nil}, {"a/x", 0, "", nil}}, "duplicate-directory": {{"a/", tar.TypeDir, "", nil}, {"a/", tar.TypeDir, "", nil}},
		"file-parent": {{"a", 0, "", nil}, {"a/x", 0, "", nil}}, "implicit-parent-file": {{"a/x", 0, "", nil}, {"a", 0, "", nil}}, "dir-to-file": {{"a/x/", tar.TypeDir, "", nil}, {"a/x", 0, "", nil}},
		"symlink": {{"a", tar.TypeSymlink, "", nil}}, "hardlink": {{"a", tar.TypeLink, "", nil}}, "fifo": {{"a", tar.TypeFifo, "", nil}}, "char": {{"a", tar.TypeChar, "", nil}}, "block": {{"a", tar.TypeBlock, "", nil}},
		"depth": {{strings.Repeat("a/", 32) + "x", 0, "", nil}}, "path-bytes": {{"root/" + strings.Repeat("x", 1024), 0, "", nil}},
		"dot-traversal": {{"./../evil", 0, "", nil}}, "double-dot-prefix": {{"././x", 0, "", nil}}, "dot-duplicate": {{"./a", 0, "", nil}, {"a", 0, "", nil}},
		"flat-symlink": {{"index.html", 0, "x", nil}, {"link", tar.TypeSymlink, "", nil}},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixtureTar(t, files...)
			if _, e := extractArtifact(context.Background(), bytes.NewReader(b), t.TempDir(), archiveTestConfig()); e == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
}
func TestArchiveMalformedAndLimits(t *testing.T) {
	good := fixtureTar(t, tarFixture{"root/file.txt", 0, "hello", nil})
	gz := fixtureGzip(t, good)
	badCRC := append([]byte(nil), gz...)
	badCRC[len(badCRC)-8] ^= 1
	cases := map[string][]byte{"not-tar": []byte("no"), "empty": fixtureTar(t), "truncated-header": good[:200], "truncated-file": good[:514], "no-terminal": good[:1024], "one-terminal": good[:1536], "trailing": append(append([]byte{}, good...), []byte("junk")...), "gzip-truncated": gz[:len(gz)-3], "gzip-crc": badCRC, "gzip-concatenated": append(append([]byte{}, gz...), gz...), "gzip-trailing": append(append([]byte{}, gz...), 0)}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := extractArtifact(context.Background(), bytes.NewReader(b), t.TempDir(), archiveTestConfig()); e == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
	cfg := archiveTestConfig()
	cfg.MaxExtractBytes = 4
	if _, e := extractArtifact(context.Background(), bytes.NewReader(good), t.TempDir(), cfg); !errors.Is(e, errArchiveLimit) {
		t.Fatalf("size: %v", e)
	}
	cfg = archiveTestConfig()
	cfg.MaxEntries = 1
	two := fixtureTar(t, tarFixture{"a/x", 0, "", nil}, tarFixture{"a/y", 0, "", nil})
	if _, e := extractArtifact(context.Background(), bytes.NewReader(two), t.TempDir(), cfg); !errors.Is(e, errArchiveLimit) {
		t.Fatalf("count: %v", e)
	}
	bomb := fixtureGzip(t, append(append([]byte{}, good...), make([]byte, 3<<20)...))
	cfg.MaxExtractBytes = 100
	if _, e := extractArtifact(context.Background(), bytes.NewReader(bomb), t.TempDir(), cfg); !errors.Is(e, errArchiveLimit) {
		t.Fatalf("stream bomb: %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := extractArtifact(ctx, bytes.NewReader(good), t.TempDir(), archiveTestConfig()); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel: %v", e)
	}
}
func TestArchiveSparseRejected(t *testing.T) {
	// Hand-craft a PAX extension: archive/tar's writer intentionally refuses to
	// emit sparse records, while its reader transparently supports them.

	keyValue := "GNU.sparse.realsize=0\n"
	records := ""
	for n := len(keyValue) + 2; ; n++ {
		prefix := strconv.Itoa(n) + " "
		if len(prefix)+len(keyValue) == n {
			records = prefix + keyValue
			break
		}
	}
	pax := fixtureTar(t, tarFixture{"PaxHeaders/root", 0, records, nil})
	pax[156] = tar.TypeXHeader
	for i := 148; i < 156; i++ {
		pax[i] = ' '
	}
	sum := 0
	for _, v := range pax[:512] {
		sum += int(v)
	}
	copy(pax[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	raw := append(pax[:len(pax)-1024], fixtureTar(t, tarFixture{"root", 0, "", nil})...)

	if _, e := extractArtifact(context.Background(), bytes.NewReader(raw), t.TempDir(), archiveTestConfig()); e == nil {
		t.Fatal("accepted sparse format")
	}
}
func TestOriginalArchiveOnly(t *testing.T) {
	root := t.TempDir()
	put(t, root, "index.html", []byte("original"))
	put(t, root, "index.html.gz", []byte("sidecar"))
	put(t, root, "index.html.br", []byte("sidecar"))
	put(t, root, ".fserver-spa", nil)
	put(t, root, ".hidden/secret", []byte("secret"))
	put(t, root, "download.gz", []byte("standalone"))
	put(t, root, "nested/file.txt", []byte("hello"))
	var b bytes.Buffer
	if e := writeOriginalArchive(context.Background(), &b, root, "site"); e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(&b)
	if e != nil {
		t.Fatal(e)
	}
	tr := tar.NewReader(z)
	names := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		names[h.Name] = true
	}
	for _, n := range []string{"site/index.html", "site/download.gz", "site/nested/file.txt"} {
		if !names[n] {
			t.Errorf("missing %s", n)
		}
	}
	for n := range names {
		if strings.Contains(n, "hidden") || strings.Contains(n, "fserver") || strings.HasSuffix(n, "index.html.gz") || strings.HasSuffix(n, "index.html.br") {
			t.Errorf("leaked %s", n)
		}
	}
	if e := os.Symlink("/etc/passwd", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if e := writeOriginalArchive(context.Background(), io.Discard, root, "site"); e == nil {
		t.Fatal("accepted stored symlink")
	}
}

func TestArchiveImplicitObjectsAreBounded(t *testing.T) {
	cfg := archiveTestConfig()
	cfg.MaxEntries = 2
	for _, files := range [][]tarFixture{{{"root/one/two/three/x", 0, "", nil}}, {{"root/a", 0, "", nil}, {"root/b", 0, "", nil}}} {
		if _, e := extractArtifact(context.Background(), bytes.NewReader(fixtureTar(t, files...)), t.TempDir(), cfg); !errors.Is(e, errArchiveLimit) {
			t.Fatalf("unbounded implicit objects: %v", e)
		}
	}
	// An explicit header confirming an existing implicit parent costs no second
	// filesystem object, although it still counts against the header budget.
	cfg.MaxEntries = 3
	if _, e := extractArtifact(context.Background(), bytes.NewReader(fixtureTar(t, tarFixture{"root/a", 0, "", nil}, tarFixture{"root/", tar.TypeDir, "", nil}, tarFixture{"root/b", 0, "", nil})), t.TempDir(), cfg); e != nil {
		t.Fatal(e)
	}
}

// Issue #11: flat archives from GNU tar, ustar and pax writers, gzipped or not,
// and "tar -C dir ." output with its "./" prefixes, publish as ZIP does.
func TestArchiveFlatTarDialects(t *testing.T) {
	files := map[string]string{"index.html": "<!doctype html><title>t</title><p>hello</p>\n", "robots.txt": "User-agent: *\nDisallow: /\n"}
	build := func(format tar.Format, prefix string, rootEntry bool) []byte {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		if rootEntry {
			if e := w.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0755, Format: format}); e != nil {
				t.Fatal(e)
			}
		}
		for _, name := range []string{"index.html", "robots.txt"} {
			h := &tar.Header{Name: prefix + name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(files[name])), Uname: "root", Gname: "root", Format: format}
			if format == tar.FormatPAX {
				h.PAXRecords = map[string]string{"mtime": "1793566295.5"}
			}
			if e := w.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			if _, e := io.WriteString(w, files[name]); e != nil {
				t.Fatal(e)
			}
		}
		if e := w.Close(); e != nil {
			t.Fatal(e)
		}
		// GNU tar and Python pad to a 10240-byte record.
		out := b.Bytes()
		return append(out, make([]byte, (10240-len(out)%10240)%10240)...)
	}
	cases := map[string][]byte{}
	for fname, format := range map[string]tar.Format{"gnu": tar.FormatGNU, "ustar": tar.FormatUSTAR, "pax": tar.FormatPAX} {
		cases[fname] = build(format, "", false)
		cases[fname+"-dot"] = build(format, "./", true)
		cases[fname+"-gz"] = fixtureGzip(t, build(format, "", false))
	}
	// Archive C from the issue, byte for byte (GNU tar 1.35, tar -czf).
	reported, e := base64.StdEncoding.DecodeString("H4sIAAAAAAAAA+3TsYrCQBDG8a19irUVNLtrYkCWVPcKPkDURQPRDcmI3tubOwvBQpvLifD/NTMwU0wxX3XchstsL4daDcb0Fmn6W3uP1ZgsVTZzuc3d3LpcGWuzLFfaDHfS3amTstVatTHKs71X8w/lx9u4ke8m6J8fKLxUUodCfHJrfFPsQ11HnzTF6N234u+1cR2lm8llwOd+mf+5e8z/wpH/f7HqQjstd+EoSz0ZfVVd2af9vNQJaQcAAAAAAAAAAAAAAPgIV3myT/QAKAAA")
	if e != nil {
		t.Fatal(e)
	}
	cases["issue-11"] = reported
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			dst := t.TempDir()
			root, e := extractArtifact(context.Background(), bytes.NewReader(b), dst, archiveTestConfig())
			if e != nil {
				t.Fatal(e)
			}
			if root != dst {
				t.Fatalf("flat archive root %q, want %q", root, dst)
			}
			entries, e := os.ReadDir(dst)
			if e != nil || len(entries) != 2 {
				t.Fatalf("entries %v %v", entries, e)
			}
			got, e := os.ReadFile(filepath.Join(dst, "robots.txt"))
			if e != nil || string(got) != files["robots.txt"] {
				t.Fatalf("robots.txt %q %v", got, e)
			}
		})
	}
	// A single wrapper is still unwrapped once.
	dst := t.TempDir()
	root, e := extractArtifact(context.Background(), bytes.NewReader(fixtureTar(t, tarFixture{"./site/", tar.TypeDir, "", nil}, tarFixture{"./site/index.html", 0, "x", nil})), dst, archiveTestConfig())
	if e != nil || root != filepath.Join(dst, "site") {
		t.Fatalf("wrapper root %q %v", root, e)
	}
}

// Refusals say which entry failed and why, and separate unsafe entries from
// malformed archives, for tar and ZIP alike.
func TestArchiveErrorsNameEntry(t *testing.T) {
	cases := []struct {
		name          string
		archive       []byte
		unsafe        bool
		entry, reason string
	}{
		{"traversal", fixtureTar(t, tarFixture{"index.html", 0, "x", nil}, tarFixture{"../evil.html", 0, "x", nil}), true, "../evil.html", "traversal"},
		{"symlink", fixtureTar(t, tarFixture{"index.html", 0, "x", nil}, tarFixture{"link", tar.TypeSymlink, "", nil}), true, "link", "symbolic links"},
		{"hardlink", fixtureTar(t, tarFixture{"link", tar.TypeLink, "", nil}), true, "link", "hard links"},
		{"fifo", fixtureTar(t, tarFixture{"pipe", tar.TypeFifo, "", nil}), true, "pipe", "FIFO"},
		{"absolute", fixtureTar(t, tarFixture{"/etc/passwd", 0, "", nil}), true, "/etc/passwd", "absolute"},
		{"duplicate", fixtureTar(t, tarFixture{"a", 0, "", nil}, tarFixture{"a", 0, "", nil}), true, "a", "duplicate"},
		{"long-name", fixtureTar(t, tarFixture{"../" + strings.Repeat("é", 400), 0, "", nil}), true, "", "traversal"},
		{"not-archive", []byte("<!doctype html>"), false, "", "not a ZIP, tar or tar.gz"},
		{"trailing", append(fixtureTar(t, tarFixture{"a", 0, "x", nil}), []byte("junk")...), false, "", "after the tar"},
		{"no-terminal", fixtureTar(t, tarFixture{"a", 0, "x", nil})[:1024], false, "", "end-of-archive"},
		{"bad-gzip", []byte{0x1f, 0x8b, 0, 0}, false, "", "gzip"},
		{"zip-traversal", fixtureZIP(t, zipFile("../evil.html", "x")), true, "../evil.html", "traversal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e := extractArtifact(context.Background(), bytes.NewReader(c.archive), t.TempDir(), archiveTestConfig())
			var ae *archiveError
			if !errors.As(e, &ae) || !errors.Is(e, errUnsafeArchive) {
				t.Fatalf("untyped refusal %v", e)
			}
			if ae.unsafe != c.unsafe || !strings.Contains(ae.reason, c.reason) {
				t.Fatalf("got unsafe=%v reason %q", ae.unsafe, ae.reason)
			}
			if c.entry != "" && ae.entry != c.entry {
				t.Fatalf("entry %q, want %q", ae.entry, c.entry)
			}
			if len(ae.entry) > maxReportedEntry+3 || !utf8.ValidString(ae.entry) {
				t.Fatalf("unbounded or invalid entry %q", ae.entry)
			}
		})
	}
}

// Issue #12: recognised but unsupported containers are named, and a tar whose
// first file name happens to look like such a magic still extracts.
func TestArchiveUnsupportedFormatsNamed(t *testing.T) {
	junk := strings.Repeat("\x00\x7f compressed payload ", 64)
	for name, magic := range map[string]string{"xz": "\xfd7zXZ\x00", "zstd": "\x28\xb5\x2f\xfd", "bzip2": "BZh91AY&SY", "7z": "7z\xbc\xaf\x27\x1c", "rar": "Rar!\x1a\x07\x01\x00", "lzip": "LZIP\x01", "lz4": "\x04\x22\x4d\x18"} {
		t.Run(name, func(t *testing.T) {
			for _, b := range [][]byte{[]byte(magic + junk), []byte(magic)} {
				_, e := extractArtifact(context.Background(), bytes.NewReader(b), t.TempDir(), archiveTestConfig())
				var ae *archiveError
				if !errors.As(e, &ae) || !ae.unsupported || !strings.Contains(ae.reason, "detected "+name) {
					t.Fatalf("got %v", e)
				}
			}
		})
	}
	for _, first := range []string{"BZh91AY&SY.txt", "LZIP-notes.txt"} {
		dst := t.TempDir()
		if _, e := extractArtifact(context.Background(), bytes.NewReader(fixtureTar(t, tarFixture{first, 0, "x", nil}, tarFixture{"index.html", 0, "x", nil})), dst, archiveTestConfig()); e != nil {
			t.Fatalf("%s: %v", first, e)
		}
	}
}
