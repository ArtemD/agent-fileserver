package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func testStore(t *testing.T) *store {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() { removeStage(root) })
	s, err := newStore(filepath.Join(root, "data"), "https://example.test/base/")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func sourceDir(t *testing.T) string { t.Helper(); return t.TempDir() }
func put(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func entries(t *testing.T, p string) []os.DirEntry {
	t.Helper()
	v, e := os.ReadDir(p)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func requireEmpty(t *testing.T, p string) {
	t.Helper()
	if got := entries(t, p); len(got) != 0 {
		t.Errorf("%s not empty: %v", p, got)
	}
}
func requireFailureClean(t *testing.T, s *store) {
	t.Helper()
	requireEmpty(t, s.staging)
	requireEmpty(t, s.public)
	for _, e := range entries(t, s.manifests) {
		if e.Name() != ".publish.lock" {
			t.Errorf("left metadata: %s", e.Name())
		}
	}
}

func TestTokens(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		token, e := newToken()
		if e != nil {
			t.Fatal(e)
		}
		raw, e := base64.RawURLEncoding.DecodeString(token)
		if e != nil || len(raw) != 16 || !validToken(token) {
			t.Fatalf("bad token %q (%v)", token, e)
		}
		if seen[token] {
			t.Fatal("duplicate token")
		}
		seen[token] = true
	}
	for _, token := range []string{"", "../x", strings.Repeat("a", 21), strings.Repeat("a", 23), strings.Repeat("a", 21) + "/", strings.Repeat("a", 21) + "=", strings.Repeat("a", 21) + "é", strings.Repeat("a", 21) + "."} {
		if validToken(token) {
			t.Errorf("accepted %q", token)
		}
	}
	for _, token := range []string{strings.Repeat("a", 22), "_-0123456789abcdefghij"} {
		if !validToken(token) {
			t.Errorf("rejected %q", token)
		}
	}
}

func TestPublishDirectoryAndManifest(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", []byte("<h1>ok</h1>"))
	put(t, src, "assets/icon.svg", []byte("<svg/>"))
	if e := os.Mkdir(filepath.Join(src, "empty"), 0700); e != nil {
		t.Fatal(e)
	}
	m, warning, e := s.publish(src, "private label", false)
	if e != nil {
		t.Fatal(e)
	}
	if warning != "" || m.Files != 2 || m.Bytes != 17 || m.SourceBasename != filepath.Base(src) || m.SPA || m.OriginalFilename != "" {
		t.Fatalf("unexpected metadata/warning: %+v %q", m, warning)
	}
	if m.URL != "https://example.test/base/"+m.Token+"/" {
		t.Fatal(m.URL)
	}
	if m.CreatedAt.IsZero() {
		t.Fatal("missing date")
	}
	requireEmpty(t, s.staging)
	release := filepath.Join(s.public, m.Token)
	err := filepath.WalkDir(release, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		mode := fs.FileMode(0444)
		if d.IsDir() {
			mode = 0555
		}
		if st.Mode().Perm() != mode {
			t.Errorf("mode %s: %v", path, st.Mode())
		}
		if strings.HasPrefix(d.Name(), ".") || strings.Contains(d.Name(), "manifest") {
			t.Errorf("metadata in public: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]fs.FileMode{s.staging: 0700, s.manifests: 0700, s.trash: 0700, s.public: 0755, filepath.Join(s.manifests, m.Token+".json"): 0600} {
		st, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode %v", path, st.Mode())
		}
	}
	data, e := os.ReadFile(filepath.Join(s.manifests, m.Token+".json"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte(src)) {
		t.Fatal("absolute path leaked")
	}
	got, e := s.info(m.Token)
	if e != nil || got != m {
		t.Fatalf("info: %+v %v", got, e)
	}
	all, e := s.list()
	if e != nil || len(all) != 1 || all[0] != m {
		t.Fatalf("list: %+v %v", all, e)
	}
}

func TestSingleFileEscapingAndBinary(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	name := "report #1 ? 50% + résumé.pdf"
	content := []byte{0, 1, 2, 255, 254, 128}
	p := put(t, src, name, content)
	m, warning, e := s.publish(p, "", false)
	if e != nil {
		t.Fatal(e)
	}
	if warning != "" || m.OriginalFilename != name || m.Files != 1 || m.Bytes != int64(len(content)) {
		t.Fatalf("%+v %q", m, warning)
	}
	if want := s.baseURL + "/" + m.Token + "/" + url.PathEscape(name); m.URL != want {
		t.Fatalf("%s != %s", m.URL, want)
	}
	u, e := url.Parse(m.URL)
	if e != nil || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("bad url %q", m.URL)
	}
	got, e := os.ReadFile(filepath.Join(s.public, m.Token, name))
	if e != nil || !bytes.Equal(got, content) {
		t.Fatalf("binary changed: %v", e)
	}
	if len(entries(t, filepath.Join(s.public, m.Token))) != 1 {
		t.Fatal("unexpected generated index")
	}
}

func TestRejectedNamesAndFiles(t *testing.T) {
	names := []string{".env", ".ENV.production", ".fserver-spa", ".git/config", "nested/.DS_Store", "nested/.private/x.txt", "nested/app.js.map", "nested/app.JS.MAP", "private.PEM", "private.KEY", "private.p12", "private.PFX", "private.kdbx", "private.keystore", "credentials", "Credentials.json", "secrets.yaml", "SECRETS/data.txt", "node_modules/pkg/index.js", "NODE_MODULES/a", "index.php", "x.PHP", "x.cgi", "x.pl", "x.py", "x.rb", "x.sh", "id_ed25519", "assets.key/index.html", "docs.map/index.html"}
	for _, ext := range []string{".map", ".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore", ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar", ".cgi", ".fcgi", ".pl", ".pm", ".py", ".pyc", ".pyo", ".rb", ".sh", ".bash", ".zsh", ".ps1"} {
		names = append(names, "directory"+strings.ToUpper(ext)+"/file.txt")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			src := sourceDir(t)
			put(t, src, name, []byte("not public"))
			_, _, e := s.publish(src, "", false)
			if e == nil {
				t.Fatalf("accepted %s", name)
			}
			if !strings.Contains(e.Error(), "refus") {
				t.Errorf("unclear error: %v", e)
			}
			requireFailureClean(t, s)
		})
	}
	for _, name := range []string{".output", "node_modules", "secrets"} {
		t.Run("sourceDir_"+name, func(t *testing.T) {
			s := testStore(t)
			src := filepath.Join(sourceDir(t), name)
			if e := os.Mkdir(src, 0700); e != nil {
				t.Fatal(e)
			}
			_, _, e := s.publish(src, "", false)
			if e == nil {
				t.Fatal("accepted forbidden source directory")
			}
			requireFailureClean(t, s)
		})
	}
}

func TestSymlinksAndSpecialFiles(t *testing.T) {
	for _, kind := range []string{"source-file", "source-dir", "nested-file", "nested-dir", "broken", "fifo", "socket", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			src := sourceDir(t)
			target := sourceDir(t)
			real := put(t, target, "safe.txt", []byte("safe"))
			operand := src
			switch kind {
			case "source-file":
				operand = filepath.Join(src, "link.txt")
				if e := os.Symlink(real, operand); e != nil {
					t.Fatal(e)
				}
			case "source-dir":
				operand = filepath.Join(src, "link")
				if e := os.Symlink(target, operand); e != nil {
					t.Fatal(e)
				}
			case "nested-file":
				if e := os.Symlink(real, filepath.Join(src, "link.txt")); e != nil {
					t.Fatal(e)
				}
			case "nested-dir":
				if e := os.Symlink(target, filepath.Join(src, "link")); e != nil {
					t.Fatal(e)
				}
			case "broken":
				if e := os.Symlink("missing", filepath.Join(src, "link")); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := syscall.Mkfifo(filepath.Join(src, "pipe"), 0600); e != nil {
					t.Fatal(e)
				}
			case "socket":
				if e := syscall.Mknod(filepath.Join(src, "socket"), syscall.S_IFSOCK|0600, 0); e != nil {
					t.Skip(e)
				}
			case "ancestor":
				if e := os.Symlink(target, filepath.Join(src, "link")); e != nil {
					t.Fatal(e)
				}
				operand = filepath.Join(src, "link", "safe.txt")
			}
			_, _, e := s.publish(operand, "", false)
			if e == nil {
				t.Fatalf("accepted %s", kind)
			}
			requireFailureClean(t, s)
		})
	}
}

func TestCopyRejectsChangedSource(t *testing.T) {
	for _, kind := range []string{"symlink", "replacement", "growth", "shrink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			src := sourceDir(t)
			put(t, src, "file.txt", []byte("abc"))
			p, e := inspectSource(src)
			if e != nil {
				t.Fatal(e)
			}
			defer p.root.Close()
			file := filepath.Join(src, "file.txt")
			switch kind {
			case "symlink":
				if e = os.Rename(file, file+".old"); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("file.txt.old", file); e != nil {
					t.Fatal(e)
				}
			case "replacement":
				if e = os.Rename(file, file+".old"); e != nil {
					t.Fatal(e)
				}
				put(t, src, "file.txt", []byte("def"))
			case "growth":
				put(t, src, "file.txt", []byte("abcdef"))
			case "shrink":
				put(t, src, "file.txt", []byte("a"))
			case "fifo":
				if e = os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e = syscall.Mkfifo(file, 0600); e != nil {
					t.Fatal(e)
				}
			}
			e = copySource(p.root, p.files[0], filepath.Join(t.TempDir(), "out"))
			if e == nil {
				t.Fatal("accepted source substitution")
			}
		})
	}
}

func TestSidecarCollisionsAndStandaloneDownloads(t *testing.T) {
	for _, suffix := range []string{".gz", ".br", ".GZ", ".BR"} {
		t.Run("collision"+suffix, func(t *testing.T) {
			s := testStore(t)
			src := sourceDir(t)
			put(t, src, "index.html", []byte("x"))
			put(t, src, "index.html"+suffix, []byte("sidecar"))
			_, _, e := s.publish(src, "", false)
			if e == nil || !strings.Contains(e.Error(), "sidecar") {
				t.Fatalf("%v", e)
			}
			requireFailureClean(t, s)
			if _, _, e = s.publish(filepath.Join(src, "index.html"+suffix), "", false); e == nil {
				t.Fatal("accepted single-file sidecar with original sibling")
			}
			requireFailureClean(t, s)
		})
	}
	s := testStore(t)
	src := sourceDir(t)
	for _, name := range []string{"archive.gz", "archive.br", "talk.pptx", "files.zip", "document.pdf", "bundle.dat"} {
		put(t, src, name, []byte{0, 1, 128, 255})
	}
	m, warning, e := s.publish(src, "", false)
	if e != nil {
		t.Fatal(e)
	}
	if warning == "" {
		t.Fatal("missing no-index warning")
	}
	if m.Files != 6 {
		t.Fatal(m.Files)
	}
}

func TestSPA(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	index := put(t, src, "index.html", []byte("spa"))
	m, _, e := s.publish(src, "", true)
	if e != nil {
		t.Fatal(e)
	}
	marker, e := os.Stat(filepath.Join(s.public, m.Token, ".fserver-spa"))
	if e != nil || marker.Size() != 0 || marker.Mode().Perm() != 0444 || !m.SPA || m.Files != 1 {
		t.Fatalf("marker: %v %v %+v", marker, e, m)
	}
	if _, e = os.Stat(filepath.Join(src, ".fserver-spa")); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal("source modified")
	}
	if _, _, e = s.publish(index, "", true); e == nil {
		t.Fatal("accepted single-file SPA")
	}
	if _, _, e = s.publish(sourceDir(t), "", true); e == nil {
		t.Fatal("accepted missing-index SPA")
	}
	requireEmpty(t, s.staging)
}

func TestCompression(t *testing.T) {
	if _, e := exec.LookPath("brotli"); e != nil {
		t.Skip("brotli not installed")
	}
	s := testStore(t)
	src := sourceDir(t)
	content := bytes.Repeat([]byte("const greeting = 'hello world';\n"), 100)
	for _, ext := range []string{"html", "css", "js", "mjs", "json", "svg", "txt", "xml", "csv", "md", "wasm"} {
		put(t, src, "asset."+ext, content)
	}
	put(t, src, "small.txt", []byte("small"))
	put(t, src, "large.bin", content)
	m, _, e := s.publish(src, "", false)
	if e != nil {
		t.Fatal(e)
	}
	for _, ext := range []string{"html", "css", "js", "mjs", "json", "svg", "txt", "xml", "csv", "md", "wasm"} {
		original := filepath.Join(s.public, m.Token, "asset."+ext)
		gz, e := os.Open(original + ".gz")
		if e != nil {
			t.Fatal(e)
		}
		z, e := gzip.NewReader(gz)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := io.ReadAll(z)
		z.Close()
		gz.Close()
		if e != nil || !bytes.Equal(decoded, content) {
			t.Fatalf("gzip %s: %v", ext, e)
		}
		decoded, e = exec.Command("brotli", "-d", "-c", "--", original+".br").Output()
		if e != nil || !bytes.Equal(decoded, content) {
			t.Fatalf("brotli %s: %v", ext, e)
		}
		for _, suffix := range []string{".gz", ".br"} {
			st, e := os.Stat(original + suffix)
			if e != nil {
				t.Fatal(e)
			}
			if st.Size() >= int64(len(content)) || st.Mode().Perm() != 0444 {
				t.Fatalf("bad sidecar %s: %v", original+suffix, st)
			}
		}
	}
	for _, name := range []string{"small.txt.gz", "small.txt.br", "large.bin.gz", "large.bin.br"} {
		if _, e = os.Stat(filepath.Join(s.public, m.Token, name)); !errors.Is(e, fs.ErrNotExist) {
			t.Fatalf("unexpected sidecar %s", name)
		}
	}
	requireEmpty(t, s.staging)
}

func TestIncompressibleSidecarsDiscarded(t *testing.T) {
	if _, e := exec.LookPath("brotli"); e != nil {
		t.Skip("brotli not installed")
	}
	s := testStore(t)
	src := sourceDir(t)
	content := make([]byte, 1024)
	// Deterministic pseudo-random input avoids flaky compressibility assertions.
	var x uint32 = 0x12345678
	for i := range content {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		content[i] = byte(x)
	}
	put(t, src, "random.wasm", content)
	m, _, e := s.publish(src, "", false)
	if e != nil {
		t.Fatal(e)
	}
	if got := len(entries(t, filepath.Join(s.public, m.Token))); got != 1 {
		t.Fatalf("kept larger compression outputs: %d", got)
	}
	requireEmpty(t, s.staging)
}

func TestCompressionFailureRollsBack(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", bytes.Repeat([]byte("hello"), 300))
	_, _, e := s.publish(src, "", false)
	if e == nil || !strings.Contains(e.Error(), "brotli") {
		t.Fatalf("%v", e)
	}
	requireFailureClean(t, s)
}

func TestActivationFailureRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root permission enforcement")
	}
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", []byte("hello"))
	if e := os.Chmod(s.public, 0555); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(s.public, 0755)
	_, _, e := s.publish(src, "", false)
	if e == nil {
		t.Fatal("expected activation failure")
	}
	requireFailureClean(t, s)
}

func TestUnpublishPreservesReleaseAndExcludesStaleManifests(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", []byte("keep me"))
	put(t, src, "nested/file.txt", []byte("nested"))
	m, _, e := s.publish(src, "private", false)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.unpublish(m.Token)
	if e != nil || got.URL != m.URL {
		t.Fatalf("unpublish: %+v %v", got, e)
	}
	if _, e = os.Stat(filepath.Join(s.public, m.Token)); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal("still public")
	}
	content, e := os.ReadFile(filepath.Join(s.trash, m.Token, "index.html"))
	if e != nil || string(content) != "keep me" {
		t.Fatalf("trash: %s %v", content, e)
	}
	for path, want := range map[string]fs.FileMode{
		filepath.Join(s.trash, m.Token):                    0555,
		filepath.Join(s.trash, m.Token, "nested"):          0555,
		filepath.Join(s.trash, m.Token, "nested/file.txt"): 0444,
	} {
		st, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != want {
			t.Errorf("unpublish changed immutable mode on %s: %v", path, st.Mode())
		}
	}
	if _, e = os.Stat(filepath.Join(s.manifests, m.Token+".json")); e != nil {
		t.Fatal("manifest not retained")
	}
	all, e := s.list()
	if e != nil || len(all) != 0 {
		t.Fatalf("listed inactive manifest: %+v %v", all, e)
	}
	if _, e = s.info(m.Token); e == nil {
		t.Fatal("info accepted inactive release")
	}
	if _, e = s.unpublish(m.Token); e == nil {
		t.Fatal("second unpublish accepted")
	}
	for _, token := range []string{"../public", strings.Repeat("a", 21) + "/", strings.Repeat("a", 23)} {
		if _, e = s.info(token); e == nil {
			t.Fatal("info accepted invalid token")
		}
		if _, e = s.unpublish(token); e == nil {
			t.Fatal("unpublish accepted invalid token")
		}
	}
}

func TestUnpublishNeverOverwritesTrash(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "file.txt", []byte("data"))
	m, _, e := s.publish(src, "", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(s.trash, m.Token), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = s.unpublish(m.Token); e == nil {
		t.Fatal("overwrote trash")
	}
	if _, e = s.info(m.Token); e != nil {
		t.Fatal("release lost")
	}
}

func TestConcurrentPublishes(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", []byte("immutable"))
	const count = 24
	var wg sync.WaitGroup
	results := make(chan manifest, count)
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, _, e := s.publish(src, fmt.Sprint(i), false)
			if e != nil {
				failures <- e
			} else {
				results <- m
			}
		}(i)
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	tokens := map[string]bool{}
	for m := range results {
		if tokens[m.Token] {
			t.Fatal("duplicate token")
		}
		tokens[m.Token] = true
	}
	if len(tokens) != count {
		t.Fatalf("published %d of %d", len(tokens), count)
	}
	all, e := s.list()
	if e != nil || len(all) != count {
		t.Fatalf("list count %d: %v", len(all), e)
	}
	requireEmpty(t, s.staging)
}

func TestConfiguration(t *testing.T) {
	for _, base := range []string{"", "http://example.test", "https://", "https://user:pass@example.test", "https://example.test/?x=1", "https://example.test/#fragment", "https://example.test/?", "file:///tmp", "example.test", "https://example.test/has space"} {
		if _, e := newStore(filepath.Join(t.TempDir(), "data"), base); e == nil {
			t.Errorf("accepted base %q", base)
		}
	}
	if _, e := newStore(filepath.Join(t.TempDir(), "data"), "https://example.test:8443/path"); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	target := t.TempDir()
	if e := os.Symlink(target, filepath.Join(root, "staging")); e != nil {
		t.Fatal(e)
	}
	if _, e := newStore(root, "https://example.test"); e == nil {
		t.Fatal("accepted symlinked storage")
	}
}

func TestCLI(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { removeStage(root) })
	t.Setenv("FSERVER_ROOT", filepath.Join(root, "data"))
	t.Setenv("FSERVER_BASE_URL", "https://example.test")
	src := sourceDir(t)
	single := put(t, src, "a file.pdf", []byte("pdf"))
	var out, diagnostics bytes.Buffer
	if e := run([]string{"--json", "--label", "private label", single}, &out, &diagnostics); e != nil {
		t.Fatal(e)
	}
	var m manifest
	if e := json.Unmarshal(out.Bytes(), &m); e != nil {
		t.Fatal(e)
	}
	if diagnostics.Len() != 0 || m.Label != "private label" || strings.Contains(m.URL, "private") {
		t.Fatalf("output %s / %s", out.String(), diagnostics.String())
	}
	out.Reset()
	if e := run([]string{"info", m.Token, "--json"}, &out, &diagnostics); e != nil {
		t.Fatal(e)
	}
	var got manifest
	if e := json.Unmarshal(out.Bytes(), &got); e != nil || got != m {
		t.Fatalf("%+v %v", got, e)
	}
	out.Reset()
	if e := run([]string{"list", "--json"}, &out, &diagnostics); e != nil {
		t.Fatal(e)
	}
	var all []manifest
	if e := json.Unmarshal(out.Bytes(), &all); e != nil || len(all) != 1 {
		t.Fatal(out.String(), e)
	}
	out.Reset()
	if e := run([]string{"unpublish", m.Token}, &out, &diagnostics); e != nil {
		t.Fatal(e)
	}
	if out.String() != m.URL+"\n" {
		t.Fatal(out.String())
	}
	out.Reset()
	if e := run([]string{"list"}, &out, &diagnostics); e != nil || out.String() != "[]\n" {
		t.Fatal(out.String(), e)
	}
	out.Reset()
	diagnostics.Reset()
	if e := run([]string{src}, &out, &diagnostics); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(diagnostics.String(), "404") || !strings.HasPrefix(out.String(), "https://example.test/") {
		t.Fatalf("%s / %s", out.String(), diagnostics.String())
	}
	out.Reset()
	if e := run([]string{"--unknown", src}, &out, &diagnostics); e == nil || out.Len() != 0 {
		t.Fatal("invalid args produced output")
	}
}

func TestArgumentParsing(t *testing.T) {
	for _, args := range [][]string{nil, {"--label"}, {"--spa"}, {"a", "b"}, {"info"}, {"info", "x", "--spa"}, {"list", "x"}, {"--no-validation", "x"}} {
		if _, e := parseArgs(args); e == nil {
			t.Errorf("accepted %q", args)
		}
	}
	a, e := parseArgs([]string{"--", "-source"})
	if e != nil || a.operand != "-source" {
		t.Fatalf("%+v %v", a, e)
	}
	a, e = parseArgs([]string{"source", "--label=a b", "--spa", "--json"})
	if e != nil || a.label != "a b" || !a.spa || !a.json {
		t.Fatalf("%+v %v", a, e)
	}
}
