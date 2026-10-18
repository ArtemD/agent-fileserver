package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
		"two-roots": {{"a", 0, "", nil}, {"b", 0, "", nil}}, "duplicate": {{"a/x", 0, "", nil}, {"a/x", 0, "", nil}}, "duplicate-directory": {{"a/", tar.TypeDir, "", nil}, {"a/", tar.TypeDir, "", nil}},
		"file-parent": {{"a", 0, "", nil}, {"a/x", 0, "", nil}}, "implicit-parent-file": {{"a/x", 0, "", nil}, {"a", 0, "", nil}}, "dir-to-file": {{"a/x/", tar.TypeDir, "", nil}, {"a/x", 0, "", nil}},
		"symlink": {{"a", tar.TypeSymlink, "", nil}}, "hardlink": {{"a", tar.TypeLink, "", nil}}, "fifo": {{"a", tar.TypeFifo, "", nil}}, "char": {{"a", tar.TypeChar, "", nil}}, "block": {{"a", tar.TypeBlock, "", nil}},
		"depth": {{strings.Repeat("a/", 32) + "x", 0, "", nil}}, "path-bytes": {{"root/" + strings.Repeat("x", 1024), 0, "", nil}},
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
