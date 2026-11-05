package main

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every error string a handler or tool can return has a next-step hint, so an
// agent never gets a bare "something failed".
func TestEveryErrorHasHint(t *testing.T) {
	call := regexp.MustCompile(`(?:apiError|apiErrorDetail|visitorError)\(w, \d+, id, "([^"]+)"|mcpFailure(?:Detail)?\("([^"]+)"`)
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(b), -1) {
			msg := m[1] + m[2]
			found++
			if strings.TrimSpace(errorHints[msg]) == "" {
				t.Errorf("%s: error %q has no hint in errorHints", f.Name(), msg)
			}
		}
	}
	if found < 60 {
		t.Fatalf("found only %d error call sites; the pattern no longer matches the code", found)
	}
	for msg, hint := range errorHints {
		if len(hint) < 30 {
			t.Errorf("hint for %q is too short to be actionable: %q", msg, hint)
		}
	}
}

func decodeErrorBody(t *testing.T, raw []byte) apiErrorBody {
	t.Helper()
	var body apiErrorBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("not an error body: %s", raw)
	}
	if body.Hint == "" || body.Hint != errorHints[body.Error] {
		t.Fatalf("missing or mismatched hint: %s", raw)
	}
	return body
}

func TestArchiveRefusalResponses(t *testing.T) {
	f := testAPI(t)
	post := func(archive []byte) apiErrorBody {
		b, ct := uploadBody(t, []byte(`{}`), archive)
		w := f.do("POST", "/_api/v1/releases", b, ct, requestID())
		assertAPIStatus(t, w, 400)
		return decodeErrorBody(t, w.Body.Bytes())
	}
	got := post(fixtureTar(t, tarFixture{"index.html", 0, "x", nil}, tarFixture{"../evil.html", 0, "x", nil}))
	if got.Error != "unsafe archive entry" || got.Entry != "../evil.html" || !strings.Contains(got.Reason, "traversal") || got.RequestID == "" {
		t.Fatalf("unsafe entry response %+v", got)
	}
	got = post([]byte("\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4\x46"))
	if got.Error != "unsupported archive format" || !strings.Contains(got.Reason, "detected xz") || !strings.Contains(got.Hint, "tar.gz") {
		t.Fatalf("unsupported response %+v", got)
	}
	got = post([]byte("this is not an archive"))
	if got.Error != "malformed archive" || got.Entry != "" || got.Reason == "" {
		t.Fatalf("malformed response %+v", got)
	}
	// Publisher refusals name the path relative to the site.
	b, ct := uploadBody(t, []byte(`{}`), fixtureTar(t, tarFixture{"index.html", 0, "x", nil}, tarFixture{"js/app.js.map", 0, "{}", nil}))
	w := f.do("POST", "/_api/v1/releases", b, ct, requestID())
	assertAPIStatus(t, w, 422)
	got = decodeErrorBody(t, w.Body.Bytes())
	if got.Error != "publisher refused artifact" || got.Entry != "js/app.js.map" || !strings.Contains(got.Reason, "source maps") {
		t.Fatalf("refusal response %+v", got)
	}
	// A flat tar from the issue publishes as a two-file site.
	v := publishAPI(t, f, `{}`, tarFixture{"index.html", 0, "<p>hi</p>", nil}, tarFixture{"robots.txt", 0, "User-agent: *\n", nil})
	if v.Files != 2 || v.OriginalFilename != "" {
		t.Fatalf("flat tar release %+v", v)
	}
}

func TestMCPErrorsCarryHints(t *testing.T) {
	f := testAPI(t)
	archive := fixtureTar(t, tarFixture{"index.html", 0, "x", nil}, tarFixture{"link", tar.TypeSymlink, "", nil})
	raw := mcpTool(t, f, "publish_archive", map[string]any{"idempotency_key": requestID(), "archive_base64": base64.StdEncoding.EncodeToString(archive)}, true)
	if got := decodeErrorBody(t, raw); got.Error != "unsafe archive entry" || got.Entry != "link" || !strings.Contains(got.Reason, "symbolic") {
		t.Fatalf("publish_archive %+v", got)
	}
	raw = mcpTool(t, f, "publish_files", map[string]any{"idempotency_key": requestID(), "files": []map[string]any{{"path": "../x.html", "text": "x"}}}, true)
	if got := decodeErrorBody(t, raw); got.Error != "invalid files" || got.Entry != "../x.html" || !strings.Contains(got.Reason, "traversal") {
		t.Fatalf("publish_files %+v", got)
	}
	raw = mcpTool(t, f, "publish_files", map[string]any{"idempotency_key": requestID(), "files": []map[string]any{{"path": "a.bin", "content_base64": "!!!!"}}}, true)
	if got := decodeErrorBody(t, raw); got.Error != "invalid files" || got.Entry != "a.bin" || !strings.Contains(got.Reason, "base64") {
		t.Fatalf("publish_files base64 %+v", got)
	}
	raw = mcpTool(t, f, "release_info", map[string]any{"token": "short"}, true)
	decodeErrorBody(t, raw)
	raw = mcpTool(t, f, "release_info", map[string]any{"token": strings.Repeat("A", 22)}, true)
	if got := decodeErrorBody(t, raw); got.Error != "release not found" {
		t.Fatalf("release_info %+v", got)
	}
}

// Release refusals reach a person in a browser through Caddy's forward_auth:
// they are a small readable page, never JSON, and keep the status, the Basic
// challenge (the only way a browser asks for the password) and the request ID.
func TestVisitorRefusalsArePagesNotJSON(t *testing.T) {
	f := testAPI(t)
	protected := publishAPI(t, f, `{"password":"privatePassword"}`, tarFixture{"a.txt", 0, "private", nil})
	for _, tc := range []struct {
		token, password string
		status          int
		title, hint     string
	}{
		{protected.Token, "", 401, "Password required", "viewer authentication required"},
		{protected.Token, "wrong-password", 401, "Password required", "viewer authentication required"},
		{strings.Repeat("A", 22), "", 404, "Link not found", "link not found"},
	} {
		r := httptest.NewRequest("GET", "/_internal/authorize", nil)
		r.Header.Set("X-Forwarded-Uri", "/"+tc.token+"/a.txt")
		r.Header.Set("X-Fserver-Client-IP", "192.0.2.97")
		if tc.password != "" {
			r.SetBasicAuth("viewer", tc.password)
		}
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		assertAPIStatus(t, w, tc.status)
		body := w.Body.String()
		if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("%d: content type %q", tc.status, ct)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("%d: no strict CSP: %v", tc.status, w.Header())
		}
		if json.Valid(w.Body.Bytes()) || strings.Contains(body, `"error"`) || strings.Contains(body, "<script") {
			t.Fatalf("%d: body is not a plain page: %s", tc.status, body)
		}
		if !strings.Contains(body, "<h1>"+tc.title+"</h1>") || !strings.Contains(body, html.EscapeString(errorHints[tc.hint])) ||
			!strings.Contains(body, w.Header().Get("X-Request-ID")) {
			t.Fatalf("%d: page lacks heading, hint or request id: %s", tc.status, body)
		}
		if strings.Contains(body, "list_releases") || strings.Contains(body, tc.token) {
			t.Fatalf("%d: page talks to agents or echoes the token: %s", tc.status, body)
		}
		challenge := w.Header().Get("WWW-Authenticate")
		if (tc.status == 401) != strings.HasPrefix(challenge, `Basic realm="fserver-`) {
			t.Fatalf("%d: WWW-Authenticate=%q", tc.status, challenge)
		}
	}
}
