package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type apiFixture struct {
	a      *apiServer
	key    string
	tokens *tokenStore
}

func testAPI(t *testing.T) apiFixture {
	t.Helper()
	s := testStore(t)
	credentials := t.TempDir()
	if e := os.Chmod(credentials, 0700); e != nil {
		t.Fatal(e)
	}
	tokens, e := newTokenStore(filepath.Join(credentials, "tokens.json"))
	if e != nil {
		t.Fatal(e)
	}
	_, key, e := tokens.Create("test agent", 0)
	if e != nil {
		t.Fatal(e)
	}
	a, e := newAPIServer(s, tokens, apiConfig{MaxUploadBytes: 2 << 20, MaxExtractBytes: 1 << 20, MaxEntries: 100, MinFreeBytes: 1, PublishLimit: 1000})
	if e != nil {
		t.Fatal(e)
	}
	return apiFixture{a, key, tokens}
}

// internal marks a test request as an in-process MCP-adapter call; the release
// core is never reachable as a public HTTP route.
func internal(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), internalCallKey{}, true))
}
func (f apiFixture) do(method, target string, body []byte, content, key string) *httptest.ResponseRecorder {
	r := internal(httptest.NewRequest(method, target, bytes.NewReader(body)))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("X-Fserver-Client-IP", "192.0.2.1")
	if content != "" {
		r.Header.Set("Content-Type", content)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	return w
}
func uploadBody(t *testing.T, meta, artifact []byte) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if e := w.SetBoundary("test-boundary-0123456789"); e != nil {
		t.Fatal(e)
	}
	p, e := w.CreateFormField("metadata")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = p.Write(meta)
	p, e = w.CreateFormFile("artifact", "../../ignored.tar")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = p.Write(artifact)
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes(), w.FormDataContentType()
}
func publishAPI(t *testing.T, f apiFixture, meta string, files ...tarFixture) releaseView {
	t.Helper()
	b, ct := uploadBody(t, []byte(meta), fixtureTar(t, files...))
	w := f.do("POST", "/_api/v1/releases", b, ct, requestID())
	if w.Code != 201 {
		t.Fatalf("publish: %d %s", w.Code, w.Body)
	}
	var v releaseView
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func assertAPIStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache=%s", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("no request id")
	}
}
func TestAPIRoutesAuthenticationAndNamespace(t *testing.T) {
	f := testAPI(t)
	f.a.cfg.Namespace = "owner-two"
	w := f.do("GET", "/_api/v1/me", nil, "", "")
	assertAPIStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"namespace":"owner-two"`) || !strings.Contains(w.Body.String(), `"max_entries":100`) {
		t.Fatal(w.Body)
	}
	for _, target := range []string{"/", "/_api/v1/tokens", "/_api/v1/releases/", "/_api/v1/me?namespace=other", "/_api/v1/%6de", "/_api/v1/../v1/me", "/_api//v1/me"} {
		assertAPIStatus(t, f.do("GET", target, nil, "", ""), 404)
	}
	for _, tc := range []struct{ method, target, allow string }{{"POST", "/_api/v1/me", "GET"}, {"PUT", "/_api/v1/releases", "GET, POST"}} {
		w = f.do(tc.method, tc.target, nil, "", "")
		assertAPIStatus(t, w, 405)
		if w.Header().Get("Allow") != tc.allow {
			t.Fatal(w.Header())
		}
	}
	original := f.key
	for i := 0; i < 11; i++ {
		f.key = "wrong"
		w = f.do("GET", "/_api/v1/me", nil, "", "")
		if i < 10 {
			assertAPIStatus(t, w, 401)
			if w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal(w.Header())
			}
		} else {
			assertAPIStatus(t, w, 429)
		}
	}
	f.key = original
	assertAPIStatus(t, f.do("GET", "/_api/v1/me", nil, "", ""), 200) // shared NAT is not global lockout
	if e := f.tokens.Revoke("test agent"); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, f.do("GET", "/_api/v1/me", nil, "", ""), 429)
	f.key = ""
	r := httptest.NewRequest("GET", "/_internal/health", nil)
	w = httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	assertAPIStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatal(w.Body)
	}
}
func TestAPIManagementPasswordDownloadDelete(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{"label":"Hello 🌎","password":"initialPassword"}`, tarFixture{"Proposal space.pdf", 0, "0123456789", nil})
	if !v.Protected || v.Username != "viewer" || v.Label != "Hello 🌎" {
		t.Fatalf("%+v", v)
	}
	base := "/_api/v1/releases/" + v.Token
	for _, target := range []string{"/_api/v1/releases", base} {
		w := f.do("GET", target, nil, "", "")
		assertAPIStatus(t, w, 200)
		for _, secret := range []string{"password_hash", "initialPassword", "$2"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("secret leaked")
			}
		}
	}
	r := internal(httptest.NewRequest("GET", base+"/download", nil))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Range", "bytes=2-5")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	assertAPIStatus(t, w, 206)
	if w.Body.String() != "2345" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal(w.Body, w.Header())
	}
	for _, bad := range []string{`{"password":""}`, `{"password":null}`, `{}`, `{"password":"short"}`, `{"password":"abcdefgh\n"}`, `{"password":"abcdefgh","unknown":true}`, `{"password":"initialPassword","Password":""}`, `{"password":"initialPassword","password":""}`} {
		assertAPIStatus(t, f.do("PUT", base+"/password", []byte(bad), "application/json", ""), 400)
		p, e := f.a.s.policy(v.Token)
		if e != nil || !p.Check("viewer", "initialPassword") {
			t.Fatalf("invalid request modified policy: %v", e)
		}
	}
	assertAPIStatus(t, f.do("PUT", base+"/password", []byte(`{"password":"newPassword"}`), "application/json", ""), 200)
	p, _ := f.a.s.policy(v.Token)
	if !p.Check("viewer", "newPassword") || p.Check("viewer", "initialPassword") {
		t.Fatal("password unchanged")
	}
	w = f.do("POST", base+"/password/reset", nil, "", "")
	assertAPIStatus(t, w, 200)
	var reset struct {
		Password string      `json:"password"`
		Username string      `json:"username"`
		Release  releaseView `json:"release"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &reset); e != nil {
		t.Fatal(e)
	}
	p, _ = f.a.s.policy(v.Token)
	if len(reset.Password) < 22 || reset.Username != "viewer" || !p.Check("viewer", reset.Password) {
		t.Fatal("reset failed")
	}
	w = f.do("DELETE", base+"/password", nil, "", "")
	assertAPIStatus(t, w, 200)
	p, _ = f.a.s.policy(v.Token)
	if p.Protected {
		t.Fatal("still protected")
	}
	old := publishAPI(t, f, `{}`, tarFixture{"old.txt", 0, "old", nil})
	if _, e := f.a.s.unpublish(old.Token); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, f.do("DELETE", base, nil, "", ""), 204)
	assertAPIStatus(t, f.do("GET", base, nil, "", ""), 404)
	for _, p := range []string{filepath.Join(f.a.s.public, v.Token), filepath.Join(f.a.s.manifests, v.Token+".json"), filepath.Join(f.a.s.policies, v.Token+".json")} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatalf("not deleted: %s %v", p, e)
		}
	}
	if _, e := os.Stat(filepath.Join(f.a.s.trash, old.Token)); e != nil {
		t.Fatal("unrelated historical trash deleted", e)
	}
}
func TestAPIDirectoryDownloadOriginals(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{"spa":true}`, tarFixture{"site/index.html", 0, strings.Repeat("hello", 600), nil}, tarFixture{"site/standalone.gz", 0, "original archive", nil})
	w := f.do("GET", "/_api/v1/releases/"+v.Token+"/download", nil, "", "")
	assertAPIStatus(t, w, 200)
	z, e := gzip.NewReader(w.Body)
	if e != nil {
		t.Fatal(e)
	}
	tr := tar.NewReader(z)
	files := map[string]string{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Typeflag == tar.TypeReg {
			b, e := io.ReadAll(tr)
			if e != nil {
				t.Fatal(e)
			}
			files[h.Name] = string(b)
		}
	}
	if len(files) != 2 || files["site/standalone.gz"] != "original archive" || files["site/index.html"] != strings.Repeat("hello", 600) {
		t.Fatalf("bad originals: %v", files)
	}
}
func TestAPIIdempotencyPersistentScopedDeletedAndAmbiguous(t *testing.T) {
	f := testAPI(t)
	meta := []byte(`{"label":"repeat"}`)
	artifact := fixtureTar(t, tarFixture{"x.txt", 0, "same", nil})
	b, ct := uploadBody(t, meta, artifact)
	key := "same-idempotency-key"
	w := f.do("POST", "/_api/v1/releases", b, ct, key)
	assertAPIStatus(t, w, 201)
	original := w.Body.String()
	var v releaseView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	a, e := newAPIServer(f.a.s, f.tokens, f.a.cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.a = a
	w = f.do("POST", "/_api/v1/releases", b, ct, key)
	assertAPIStatus(t, w, 201)
	if w.Body.String() != original {
		t.Fatal("replay changed")
	}
	ms, e := a.s.list()
	if e != nil || len(ms) != 1 {
		t.Fatal("republished", ms, e)
	}
	changed, _ := uploadBody(t, []byte(`{"label":"different"}`), artifact)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", changed, ct, key), 409)
	_, second, e := f.tokens.Create("other", 0)
	if e != nil {
		t.Fatal(e)
	}
	first := f.key
	f.key = second
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, key), 201)
	f.key = first
	assertAPIStatus(t, f.do("DELETE", "/_api/v1/releases/"+v.Token, nil, "", ""), 204)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, key), 409)
	identity, e := f.tokens.Authenticate(f.key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	pendingKey := "ambiguous-key-012345"
	kh := sha256.Sum256([]byte(identity.ID + "\x00" + pendingKey))
	canonical, _ := json.Marshal(uploadMetadata{Label: "repeat"})
	h := sha256.New()
	h.Write(canonical)
	h.Write([]byte{0})
	h.Write(artifact)
	rp := filepath.Join(a.state, hex.EncodeToString(kh[:])+".json")
	if e = a.writeReplay(rp, apiReplay{Created: time.Now(), Digest: hex.EncodeToString(h.Sum(nil)), State: "pending"}); e != nil {
		t.Fatal(e)
	}
	w = f.do("POST", "/_api/v1/releases", b, ct, pendingKey)
	assertAPIStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), "ambiguous") || !strings.Contains(w.Body.String(), "list your uploads") {
		t.Fatal(w.Body)
	}
	requireEmpty(t, a.incoming)
}
func TestAPIUploadValidationLimitsAndCleanups(t *testing.T) {
	for _, tc := range []struct {
		name, meta string
		files      []tarFixture
		status     int
	}{
		{"hidden", `{}`, []tarFixture{{"root/.env", 0, "secret", nil}}, 422}, {"source", `{}`, []tarFixture{{"app.py", 0, "", nil}}, 422}, {"sidecars", `{}`, []tarFixture{{"root/a.txt", 0, "a", nil}, {"root/a.txt.gz", 0, "x", nil}}, 422}, {"spa-file", `{"spa":true}`, []tarFixture{{"a.txt", 0, "a", nil}}, 422},
		{"bad-label", `{"label":"bad\nlabel"}`, []tarFixture{{"a.txt", 0, "", nil}}, 400}, {"unknown-meta", `{"path":"/etc/passwd"}`, nil, 400}, {"traversal", `{}`, []tarFixture{{"../x", 0, "", nil}}, 400}, {"hardlink", `{}`, []tarFixture{{"x", tar.TypeLink, "", nil}}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testAPI(t)
			b, ct := uploadBody(t, []byte(tc.meta), fixtureTar(t, tc.files...))
			w := f.do("POST", "/_api/v1/releases", b, ct, requestID())
			assertAPIStatus(t, w, tc.status)
			requireEmpty(t, f.a.incoming)
			requireEmpty(t, f.a.s.public)
			if strings.Contains(w.Body.String(), f.a.s.root) {
				t.Fatal("filesystem path leaked")
			}
		})
	}
	f := testAPI(t)
	good := fixtureTar(t, tarFixture{"x", 0, "abcde", nil})
	b, ct := uploadBody(t, []byte(`{}`), good)
	for _, badKey := range []string{"", "short", "123456789012345!", "123456789012345="} {
		assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, badKey), 400)
	}
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", append(append([]byte{}, b...), []byte("epilogue")...), ct, requestID()), 400)
	var extra bytes.Buffer
	mw := multipart.NewWriter(&extra)
	for _, part := range []string{"metadata", "artifact", "extra"} {
		p, _ := mw.CreateFormField(part)
		if part == "metadata" {
			_, _ = p.Write([]byte(`{}`))
		} else {
			_, _ = p.Write(good)
		}
	}
	_ = mw.Close()
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", extra.Bytes(), mw.FormDataContentType(), requestID()), 400)
	f.a.cfg.MaxUploadBytes = 10
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 413)
	f.a.cfg.MaxUploadBytes = 2 << 20
	f.a.cfg.MaxExtractBytes = 4
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 413)
	f.a.cfg.MinFreeBytes = ^uint64(0)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 507)
	requireEmpty(t, f.a.incoming)
}
func TestAPIRatesBusyAndCancellation(t *testing.T) {
	f := testAPI(t)
	b, ct := uploadBody(t, []byte(`{}`), fixtureTar(t, tarFixture{"x", 0, "hello", nil}))
	f.a.job <- struct{}{}
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 429)
	<-f.a.job
	f.a.cfg.PublishLimit = 1
	f.a.mu.Lock()
	f.a.rates = map[string]apiRate{}
	f.a.mu.Unlock()
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 201)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 429)
	f = testAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/_api/v1/releases", bytes.NewReader(b)).WithContext(context.WithValue(ctx, internalCallKey{}, true))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Idempotency-Key", requestID())
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	assertAPIStatus(t, w, 408)
	requireEmpty(t, f.a.incoming)
	requireEmpty(t, f.a.s.public)
	for i := 0; i < 5000; i++ {
		f.a.rate(fmt.Sprintf("ip:%d", i), 10, time.Minute, true)
	}
	if len(f.a.rates) > 4096 {
		t.Fatalf("unbounded rates %d", len(f.a.rates))
	}
	f.a.mu.Lock()
	f.a.rates["old"] = apiRate{count: 10, since: time.Now().Add(-2 * time.Minute)}
	f.a.mu.Unlock()
	if !f.a.rate("old", 10, time.Minute, true) {
		t.Fatal("rate did not expire")
	}
}
func TestAPIInternalAuthorizeCanonicalAndFailClosed(t *testing.T) {
	f := testAPI(t)
	public := publishAPI(t, f, `{}`, tarFixture{"a.txt", 0, "public", nil})
	protected := publishAPI(t, f, `{"password":"privatePassword"}`, tarFixture{"b.txt", 0, "private", nil})
	check := func(uri, user, pwd string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_internal/authorize", nil)
		r.Header.Set("X-Forwarded-Uri", uri)
		r.Header.Set("X-Fserver-Client-IP", "192.0.2.99")
		if user != "" {
			r.SetBasicAuth(user, pwd)
		}
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		return w
	}
	w := check("/"+public.Token+"/a.txt", "", "")
	assertAPIStatus(t, w, 204)
	if w.Header().Get("X-Fserver-Cache-Control") != "public, max-age=3600" {
		t.Fatal(w.Header())
	}
	w = check("/"+protected.Token+"/b.txt", "", "")
	assertAPIStatus(t, w, 401)
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), protected.Token) {
		t.Fatal(w.Header())
	}
	w = check("/"+protected.Token+"/b.txt", "viewer", "privatePassword")
	assertAPIStatus(t, w, 204)
	if w.Header().Get("X-Fserver-Cache-Control") != "private, no-store" {
		t.Fatal(w.Header())
	}
	for _, uri := range []string{"/" + public.Token + "/../" + protected.Token + "/b.txt", "/" + public.Token + "/%2e%2e/" + protected.Token + "/b.txt", "/" + public.Token + "/%2E%2e%2f" + protected.Token + "/b.txt", "/" + public.Token + "\\..\\" + protected.Token, "//" + public.Token + "/a.txt", "/" + public.Token + "//a.txt", "/" + public.Token + "/.hidden", "https://evil/" + public.Token, "/" + public.Token + "/%zz", "/" + public.Token + "/a.txt#x", "/" + public.Token + "#/a.txt", "/" + public.Token + "/a.txt?a=1#x"} {
		assertAPIStatus(t, check(uri, "", ""), 404)
	}
	if e := os.WriteFile(filepath.Join(f.a.s.policies, public.Token+".json"), []byte(`{"protected":false,"password_hash":"malformed"}`), 0600); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, check("/"+public.Token+"/a.txt", "", ""), 404)
	if e := os.Remove(filepath.Join(f.a.s.policies, protected.Token+".json")); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, check("/"+protected.Token+"/b.txt", "viewer", "privatePassword"), 404)
}

// Caddy's forward_auth carries the visitor's query (even a bare "?") onto
// /_internal/authorize. It must neither break nor change the authorized URI.
func TestAPIInternalAuthorizeIgnoresVisitorQuery(t *testing.T) {
	f := testAPI(t)
	public := publishAPI(t, f, `{}`, tarFixture{"index.html", 0, "public", nil})
	protected := publishAPI(t, f, `{"password":"privatePassword"}`, tarFixture{"index.html", 0, "private", nil})
	check := func(query, uri, user, pwd string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_internal/authorize"+query, nil)
		if (query == "?") != r.URL.ForceQuery {
			t.Fatalf("request %q: ForceQuery=%v", query, r.URL.ForceQuery)
		}
		r.Header.Set("X-Forwarded-Uri", uri+query)
		r.Header.Set("X-Fserver-Client-IP", "192.0.2.98")
		if user != "" {
			r.SetBasicAuth(user, pwd)
		}
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		return w
	}
	queries := []string{"", "?", "?a=1", "?fbclid=x&utm_source=y", "?p=..%2F..%2F" + protected.Token + "%2Findex.html", "?/../" + protected.Token + "/index.html", "?%2e%2e/%2e%2e/etc/passwd"}
	for _, q := range queries {
		w := check(q, "/"+public.Token+"/index.html", "", "")
		assertAPIStatus(t, w, 204)
		if w.Header().Get("X-Fserver-Cache-Control") != "public, max-age=3600" {
			t.Fatal(q, w.Header())
		}
		if token, ok := authorizedURIToken("/" + public.Token + "/index.html" + q); !ok || token != public.Token {
			t.Fatalf("query %q changed the authorized token", q)
		}
		w = check(q, "/"+protected.Token+"/index.html", "", "")
		assertAPIStatus(t, w, 401)
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), protected.Token) {
			t.Fatal(q, w.Header())
		}
		w = check(q, "/"+protected.Token+"/index.html", "viewer", "privatePassword")
		assertAPIStatus(t, w, 204)
		if w.Header().Get("X-Fserver-Cache-Control") != "private, no-store" {
			t.Fatal(q, w.Header())
		}
		for _, uri := range []string{"/" + public.Token + "/../" + protected.Token + "/index.html", "/" + public.Token + "/%2e%2e/" + protected.Token + "/index.html", "/" + public.Token + "/%2E%2e%2f" + protected.Token + "/index.html", "/" + public.Token + "//index.html", "/" + public.Token + "/.hidden", "https://evil/" + public.Token, "//" + public.Token + "/index.html", "/" + public.Token + "/index.html#x"} {
			assertAPIStatus(t, check(q, uri, "", ""), 404)
		}
	}
	// Only the authorize hop ignores its query; its path stays canonical.
	for _, target := range []string{"/_internal/%61uthorize?a=1", "/_internal/authorize/?a=1", "/_internal//authorize?a=1", "/_internal/health?a=1", "/_internal/health?"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("X-Forwarded-Uri", "/"+public.Token+"/index.html")
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		assertAPIStatus(t, w, 404)
	}
}
func TestAPICleanupOnlyOwnedStaleFilesAndReplayExpiry(t *testing.T) {
	f := testAPI(t)
	keep := put(t, f.a.incoming, "user-owned/data", []byte("keep"))
	stale := put(t, f.a.incoming, "api-extract-stale/data", []byte("stale"))
	old := time.Now().Add(-25 * time.Hour)
	if e := os.Chtimes(filepath.Dir(stale), old, old); e != nil {
		t.Fatal(e)
	}
	recent := put(t, f.a.incoming, "api-upload-recent", nil)
	name := strings.Repeat("a", 64) + ".json"
	rp := filepath.Join(f.a.state, name)
	if e := f.a.writeReplay(rp, apiReplay{Created: old, Digest: "x", State: "pending"}); e != nil {
		t.Fatal(e)
	}
	if e := f.a.cleanup(time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{keep, recent} {
		if _, e := os.Stat(p); e != nil {
			t.Fatal("deleted nonstale/nonowned file", e)
		}
	}
	for _, p := range []string{stale, rp} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatal("did not remove owned stale file", p, e)
		}
	}
}
func TestAPIConcurrentReadsAndSameKey(t *testing.T) {
	f := testAPI(t)
	b, ct := uploadBody(t, []byte(`{}`), fixtureTar(t, tarFixture{"x", 0, "hello", nil}))
	key := requestID()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.do("POST", "/_api/v1/releases", b, ct, key)
			if w.Code != 201 && w.Code != 429 {
				t.Errorf("unexpected %d %s", w.Code, w.Body)
			}
			assertAPIStatus(t, f.do("GET", "/_api/v1/releases", nil, "", ""), 200)
		}()
	}
	wg.Wait()
	ms, e := f.a.s.list()
	if e != nil || len(ms) != 1 {
		t.Fatal("not single publication", len(ms), e)
	}
	requireEmpty(t, f.a.incoming)
}

func TestAPIReplayPasswordUsesBcryptAndCurrentPolicy(t *testing.T) {
	f := testAPI(t)
	artifact := fixtureTar(t, tarFixture{"x", 0, "known contents", nil})
	meta := []byte(`{"label":"protected","password":"originalPassword"}`)
	b, ct := uploadBody(t, meta, artifact)
	key := requestID()
	w := f.do("POST", "/_api/v1/releases", b, ct, key)
	assertAPIStatus(t, w, 201)
	var v releaseView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	identity, e := f.tokens.Authenticate(f.key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	kh := sha256.Sum256([]byte(identity.ID + "\x00" + key))
	rp := filepath.Join(f.a.state, hex.EncodeToString(kh[:])+".json")
	record, e := readReplay(rp)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(record.PasswordHash, "$2") || record.PasswordHash == "" {
		t.Fatal("no slow password binding")
	}
	canonical, _ := json.Marshal(uploadMetadata{Label: "protected"})
	h := sha256.New()
	h.Write(canonical)
	h.Write([]byte{0})
	h.Write(artifact)
	if record.Digest != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("digest contains password")
	}
	raw, e := os.ReadFile(rp)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("originalPassword")) {
		t.Fatal("plaintext persisted")
	}
	changed, _ := uploadBody(t, []byte(`{"label":"protected","password":"differentPassword"}`), artifact)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", changed, ct, key), 409)
	omitted, _ := uploadBody(t, []byte(`{"label":"protected"}`), artifact)
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", omitted, ct, key), 409)
	base := "/_api/v1/releases/" + v.Token
	assertAPIStatus(t, f.do("DELETE", base+"/password", nil, "", ""), 200)
	w = f.do("POST", "/_api/v1/releases", b, ct, key)
	assertAPIStatus(t, w, 201)
	v = releaseView{}
	if e = json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	if v.Protected || v.Username != "" {
		t.Fatal("returned stale protection")
	}
	assertAPIStatus(t, f.do("PUT", base+"/password", []byte(`{"password":"anotherPassword"}`), "application/json", ""), 200)
	w = f.do("POST", "/_api/v1/releases", b, ct, key)
	assertAPIStatus(t, w, 201)
	v = releaseView{}
	if e = json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	if !v.Protected || v.Username != "viewer" {
		t.Fatal("returned stale public policy")
	}
	if e = os.WriteFile(filepath.Join(f.a.s.policies, v.Token+".json"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, key), 500)
}
func TestAPIStrictJSONAndMultipartOrdering(t *testing.T) {
	f := testAPI(t)
	artifact := fixtureTar(t, tarFixture{"x", 0, "hi", nil})
	for _, meta := range []string{`null`, `[]`, `{"label":null}`, `{"password":null}`, `{"password":"oldsecret","Password":""}`, `{"password":"oldsecret","password":""}`, `{"Label":"x"}`, `{"label":"first","label":"last"}`, `{"spa":null}`, `{"spa":true,"SPA":false}`, `{"label":"` + strings.Repeat("x", 201) + `"}`, `{"label":"` + strings.Repeat("x", 16384) + `"}`} {
		b, ct := uploadBody(t, []byte(meta), artifact)
		assertAPIStatus(t, f.do("POST", "/_api/v1/releases", b, ct, requestID()), 400)
	}
	requireEmpty(t, f.a.s.public)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	p, _ := mw.CreateFormFile("artifact", "x.tar")
	_, _ = p.Write(artifact)
	p, _ = mw.CreateFormField("metadata")
	_, _ = p.Write([]byte(`{}`))
	_ = mw.Close()
	assertAPIStatus(t, f.do("POST", "/_api/v1/releases", buf.Bytes(), mw.FormDataContentType(), requestID()), 400)
}
func TestAPIExpiredIdempotencyRecordsArePruned(t *testing.T) {
	f := testAPI(t)
	rp := filepath.Join(f.a.state, strings.Repeat("d", 64)+".json")
	if e := f.a.writeReplay(rp, apiReplay{Created: time.Now().Add(-25 * time.Hour), Digest: "old", State: "pending"}); e != nil {
		t.Fatal(e)
	}
	publishAPI(t, f, `{}`, tarFixture{"x", 0, "hi", nil})
	if _, e := os.Stat(rp); !os.IsNotExist(e) {
		t.Fatal("old record retained", e)
	}
}

func TestAPIViewerGuessesCacheAndPolicyInvalidation(t *testing.T) {
	f := testAPI(t)
	a := publishAPI(t, f, `{"password":"password-A"}`, tarFixture{"a", 0, "a", nil})
	b := publishAPI(t, f, `{"password":"password-B"}`, tarFixture{"b", 0, "b", nil})
	c := publishAPI(t, f, `{"password":"password-C"}`, tarFixture{"c", 0, "c", nil})
	check := func(token, password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_internal/authorize", nil)
		r.Header.Set("X-Forwarded-Uri", "/"+token+"/file")
		r.Header.Set("X-Fserver-Client-IP", "192.0.2.100")
		if password != "" {
			r.SetBasicAuth("viewer", password)
		}
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		return w
	}
	assertAPIStatus(t, check(a.Token, "password-A"), 204)
	for i := 0; i < 10; i++ {
		w := check(a.Token, "wrong-pass")
		if i < 9 {
			assertAPIStatus(t, w, 401)
		} else {
			assertAPIStatus(t, w, 429)
		}
	}
	assertAPIStatus(t, check(a.Token, "password-A"), 204) // already authenticated asset requests bypass budget
	for i := 0; i < 25; i++ {
		assertAPIStatus(t, check(b.Token, ""), 401)
	} // negative verification is cheap and not a guessed password
	for i := 0; i < 10; i++ {
		assertAPIStatus(t, check(b.Token, "wrong-pass"), 401)
	}
	assertAPIStatus(t, check(b.Token, "password-B"), 429) // bounded pre-bcrypt budget; new login tradeoff
	assertAPIStatus(t, check(c.Token, "password-C"), 204) // no cross-release/global NAT lockout
	p, e := makeAccessPolicy("new-password-A")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.s.setPolicy(a.Token, p); e != nil {
		t.Fatal(e)
	}
	assertAPIStatus(t, check(a.Token, "password-A"), 429) // old cached hash cannot bypass current policy or budget
	f.a.mu.Lock()
	delete(f.a.rates, "viewer-guess:192.0.2.100:"+a.Token)
	f.a.mu.Unlock()
	assertAPIStatus(t, check(a.Token, "password-A"), 401)
	assertAPIStatus(t, check(a.Token, "new-password-A"), 204)
	for i := 0; i < 600; i++ {
		var key [32]byte
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		f.a.rememberViewer(key)
	}
	if len(f.a.viewerCache) > 512 {
		t.Fatal("unbounded viewer cache")
	}
	var expired [32]byte
	f.a.mu.Lock()
	f.a.viewerCache[expired] = time.Now().Add(-time.Second)
	f.a.mu.Unlock()
	if f.a.cachedViewer(expired) {
		t.Fatal("expired cache entry accepted")
	}
}
func TestAPIAuthorizeLiteralPercentNamesAndSingleDecode(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{}`, tarFixture{"report #1 ? 50% + résumé.pdf", 0, "old content", nil})
	for _, uri := range []string{strings.TrimPrefix(v.URL, f.a.s.baseURL), "/" + v.Token + "/literal%2525.txt", "/" + v.Token + "/50%25.txt", "/" + v.Token + "/%252e%252e/other", "/" + v.Token + "/%252fother", "/" + v.Token + "/%255cother", "/" + v.Token + "/%2500x"} {
		r := httptest.NewRequest("GET", "/_internal/authorize", nil)
		r.Header.Set("X-Forwarded-Uri", uri)
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		assertAPIStatus(t, w, 204)
		token, ok := authorizedURIToken(uri)
		if !ok || token != v.Token {
			t.Fatal("wrong once-decoded token")
		}
		parsed, e := url.ParseRequestURI(uri)
		if e != nil {
			t.Fatal(e)
		}
		served := path.Clean(parsed.Path)
		if strings.Split(strings.TrimPrefix(served, "/"), "/")[0] != token {
			t.Fatalf("authorize differs from Caddy normalization: %q -> %q", uri, served)
		}
	}
}

func TestAPIDiskAvailableBytesAndInodes(t *testing.T) {
	cfg := apiConfig{MinFreeBytes: 4096, MaxEntries: 5000}
	required := minFreeInodes + 5*uint64(cfg.MaxEntries) + 32
	good := syscall.Statfs_t{Bsize: 4096, Bavail: 3, Files: 100000, Ffree: required}
	if !apiDiskAvailable(good, cfg, 8192) {
		t.Fatal("exact byte and inode headroom must pass")
	}
	lowBytes := good
	lowBytes.Bavail = 2
	if apiDiskAvailable(lowBytes, cfg, 8192) {
		t.Fatal("accepted insufficient bytes")
	}
	lowInodes := good
	lowInodes.Ffree = required - 1
	if apiDiskAvailable(lowInodes, cfg, 8192) {
		t.Fatal("accepted insufficient inodes")
	}
	zeroInodes := good
	zeroInodes.Ffree = 0
	if apiDiskAvailable(zeroInodes, cfg, 8192) {
		t.Fatal("accepted exhausted fixed inodes")
	}
	dynamic := zeroInodes
	dynamic.Files = 0
	if !apiDiskAvailable(dynamic, cfg, 8192) {
		t.Fatal("dynamic-inode filesystem should skip inode guard")
	}
	invalid := good
	invalid.Bsize = 0
	if apiDiskAvailable(invalid, cfg, 8192) {
		t.Fatal("accepted invalid filesystem block size")
	}
	f := testAPI(t)
	w := f.do("GET", "/_api/v1/me", nil, "", "")
	assertAPIStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"min_free_inodes":20000`) {
		t.Fatal("inode reserve missing from limits", w.Body)
	}
}

func TestPublicHTTPOnlyServesMCP(t *testing.T) {
	f := testAPI(t)
	for _, target := range []string{"/_api/v1/me", "/_api/v1/releases", "/_api/v1/releases/AAAAAAAAAAAAAAAAAAAAAA", "/", "/mcp/", "/mcp?a=1", "/mcp?", "/api"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			r := httptest.NewRequest(method, target, nil)
			r.Header.Set("Authorization", "Bearer "+f.key)
			w := httptest.NewRecorder()
			f.a.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Fatalf("%s %s: status %d, want 404 (MCP is the only public interface)", method, target, w.Code)
			}
		}
	}
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-06-18")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("MCP tools/list: status %d", w.Code)
	}
}
