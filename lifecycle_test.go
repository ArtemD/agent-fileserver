package main

// Tests for the release lifecycle: expiry (set_expiry, sweeper, authorize),
// update in place, list_releases totals and the server_info disk report.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// lifecycleAPI is testAPI with an adjustable configuration.
func lifecycleAPI(t *testing.T, adjust func(*apiConfig)) apiFixture {
	t.Helper()
	f := testAPI(t)
	cfg := f.a.cfg
	adjust(&cfg)
	a, err := newAPIServer(f.a.s, f.tokens, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	return f
}

func fileArgs(path, text string, extra map[string]any) map[string]any {
	args := map[string]any{"idempotency_key": requestID(), "files": []map[string]any{{"path": path, "text": text}}}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

// mcpView calls a tool that returns a release view and decodes it.
func mcpView(t *testing.T, f apiFixture, tool string, args map[string]any) (releaseView, string) {
	t.Helper()
	raw := mcpTool(t, f, tool, args, false)
	var v releaseView
	if err := json.Unmarshal(raw, &v); err != nil || !validToken(v.Token) {
		t.Fatalf("%s result %s (%v)", tool, raw, err)
	}
	return v, string(raw)
}

// mcpRefused calls a tool that must fail inside the tool and returns the error body.
func mcpRefused(t *testing.T, f apiFixture, tool string, args map[string]any) apiErrorBody {
	t.Helper()
	var e apiErrorBody
	if err := json.Unmarshal(mcpTool(t, f, tool, args, true), &e); err != nil || e.Error == "" {
		t.Fatalf("%s: not an error body (%v)", tool, err)
	}
	return e
}

// postRelease publishes a tar through the internal release core with raw metadata.
func postRelease(t *testing.T, f apiFixture, meta string, files ...tarFixture) *httptest.ResponseRecorder {
	t.Helper()
	b, ct := uploadBody(t, []byte(meta), fixtureTar(t, files...))
	return f.do("POST", "/_api/v1/releases", b, ct, requestID())
}

func wantAPIError(t *testing.T, w *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	assertAPIStatus(t, w, status)
	var e apiErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error != msg || e.Hint == "" {
		t.Fatalf("want %q with a hint, got %s", msg, w.Body)
	}
}

func near(t *testing.T, got *time.Time, want time.Time) {
	t.Helper()
	if got == nil {
		t.Fatalf("expires_at is null, want about %s", want)
	}
	if d := got.Sub(want); d < -time.Minute || d > time.Minute {
		t.Fatalf("expires_at %s, want about %s", got, want)
	}
}

func authorizeStatus(f apiFixture, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/_internal/authorize", nil)
	r.Header.Set("X-Forwarded-Uri", "/"+token+"/a.txt")
	r.Header.Set("X-Fserver-Client-IP", "192.0.2.99")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	return w
}

func TestLifecycleExpiryOnPublish(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	now := time.Now()

	v, raw := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", map[string]any{"expires_in_days": 7}))
	near(t, v.ExpiresAt, now.Add(7*24*time.Hour))
	if !strings.Contains(v.Notice, "set_expiry") || !strings.Contains(raw, `"expires_at":"`) {
		t.Fatalf("explicit expiry: %s", raw)
	}

	v, raw = mcpView(t, f, "publish_files", fileArgs("a.txt", "a", map[string]any{"expires_in_days": 0}))
	if v.ExpiresAt != nil || !strings.Contains(raw, `"expires_at":null`) || !strings.Contains(v.Notice, "set_expiry") {
		t.Fatalf("0 must never expire: %s", raw)
	}

	v, _ = mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	near(t, v.ExpiresAt, now.Add(60*24*time.Hour))
	if !strings.Contains(v.Notice, "set_expiry") {
		t.Fatalf("default expiry notice: %q", v.Notice)
	}

	// list_releases and release_info show expires_at but carry no notice.
	info, _ := mcpView(t, f, "release_info", map[string]any{"token": v.Token})
	if info.Notice != "" || info.ExpiresAt == nil {
		t.Fatalf("release_info: %+v", info)
	}
}

func TestLifecycleExpiryZeroDefaultNeverExpires(t *testing.T) {
	f := testAPI(t) // zero DefaultExpiryDays
	v, raw := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	if v.ExpiresAt != nil || !strings.Contains(raw, `"expires_at":null`) {
		t.Fatalf("zero default must not expire: %s", raw)
	}
}

func TestLifecycleExpiryInvalidValuesRefused(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	const msg = "expires_in_days must be an integer from 0 to 3650"
	for _, days := range []int{-1, 3651} {
		w := postRelease(t, f, fmt.Sprintf(`{"expires_in_days":%d}`, days), tarFixture{"a.txt", 0, "a", nil})
		wantAPIError(t, w, 400, msg)
		w = f.do("POST", "/_api/v1/uploads", mustJSON(t, map[string]any{"size": 1, "sha256": sumHex([]byte("x")), "idempotency_key": requestID(), "expires_in_days": days}), "application/json", "")
		wantAPIError(t, w, 400, msg)
		// The MCP schema layer refuses it too, and nothing is published.
		body := mcpPost(t, f, "tools/call", map[string]any{"name": "publish_files", "arguments": fileArgs("a.txt", "a", map[string]any{"expires_in_days": days})}).Body.String()
		if !strings.Contains(body, `"isError":true`) && !strings.Contains(body, `"error":{`) {
			t.Fatalf("MCP accepted expires_in_days=%d: %.300s", days, body)
		}
	}
	if ms, err := f.a.s.list(); err != nil || len(ms) != 0 {
		t.Fatalf("invalid expiry published something: %v %v", ms, err)
	}
	// Server configuration is bounded the same way.
	if _, err := newAPIServer(f.a.s, f.tokens, apiConfig{MaxUploadBytes: 1, MaxExtractBytes: 1, MaxEntries: 1, DefaultExpiryDays: 3651}); err == nil {
		t.Fatal("accepted DefaultExpiryDays 3651")
	}
}

func TestLifecycleLegacyManifestNeverExpires(t *testing.T) {
	var m manifest
	legacy := `{"token":"AAAAAAAAAAAAAAAAAAAAAA","url":"https://x/AAAAAAAAAAAAAAAAAAAAAA/","created_at":"2020-01-01T00:00:00Z","files":1,"bytes":1}`
	if err := json.Unmarshal([]byte(legacy), &m); err != nil || m.ExpiresAt != nil || m.UpdatedAt != nil {
		t.Fatalf("legacy decode: %+v %v", m, err)
	}
	if m.expired(time.Now().Add(100 * 365 * 24 * time.Hour)) {
		t.Fatal("a legacy manifest must never expire")
	}

	// On disk: strip expires_at from a real manifest; the sweeper keeps it.
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 1 })
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	p := filepath.Join(f.a.s.manifests, v.Token+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "expires_at")
	if err = os.WriteFile(p, mustJSON(t, fields), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := f.a.sweepExpired(time.Now().Add(1000 * 24 * time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("sweep deleted a legacy release: %d %v", n, err)
	}
	assertAPIStatus(t, f.do("GET", "/_api/v1/releases/"+v.Token, nil, "", ""), 200)
}

func TestLifecycleSetExpiryTool(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	now := time.Now()

	got, _ := mcpView(t, f, "set_expiry", map[string]any{"token": v.Token, "expires_in_days": 5})
	near(t, got.ExpiresAt, now.Add(5*24*time.Hour))
	if got.Token != v.Token || !strings.Contains(got.Notice, "set_expiry") {
		t.Fatalf("set_expiry result: %+v", got)
	}
	info, _ := mcpView(t, f, "release_info", map[string]any{"token": v.Token})
	near(t, info.ExpiresAt, now.Add(5*24*time.Hour))

	got, raw := mcpView(t, f, "set_expiry", map[string]any{"token": v.Token, "expires_in_days": 0})
	if got.ExpiresAt != nil || !strings.Contains(raw, `"expires_at":null`) || got.Notice == "" {
		t.Fatalf("0 must remove the expiry: %s", raw)
	}
	m, err := f.a.s.info(v.Token)
	if err != nil || m.ExpiresAt != nil {
		t.Fatalf("manifest: %+v %v", m, err)
	}

	// Refusals: tool-level argument errors and an unknown release.
	for name, args := range map[string]map[string]any{
		"bad token":        {"token": "short", "expires_in_days": 1},
		"missing token":    {"expires_in_days": 1},
		"null days":        {"token": v.Token, "expires_in_days": nil},
		"string days":      {"token": v.Token, "expires_in_days": "7"},
		"unexpected field": {"token": v.Token, "expires_in_days": 1, "extra": true},
	} {
		body := mcpPost(t, f, "tools/call", map[string]any{"name": "set_expiry", "arguments": args}).Body.String()
		if !strings.Contains(body, `"isError":true`) && !strings.Contains(body, `"error":{`) {
			t.Fatalf("%s accepted: %.300s", name, body)
		}
	}
	// A call that reaches the tool body with a bad token reports the stable error.
	e := mcpRefused(t, f, "set_expiry", map[string]any{"token": "bad token!", "expires_in_days": 1})
	if e.Error != "invalid set_expiry arguments" || e.Hint == "" {
		t.Fatalf("bad token: %+v", e)
	}
	e = mcpRefused(t, f, "set_expiry", map[string]any{"token": "AAAAAAAAAAAAAAAAAAAAAA", "expires_in_days": 1})
	if e.Error != "release not found" || e.Hint == "" {
		t.Fatalf("unknown token: %+v", e)
	}
	// Out-of-range values through the release core.
	w := f.do("PUT", "/_api/v1/releases/"+v.Token+"/expiry", []byte(`{"expires_in_days":3651}`), "application/json", "")
	wantAPIError(t, w, 400, "expires_in_days must be an integer from 0 to 3650")
	w = f.do("PUT", "/_api/v1/releases/"+v.Token+"/expiry", []byte(`{}`), "application/json", "")
	wantAPIError(t, w, 400, "expires_in_days must be an integer from 0 to 3650")
}

func TestLifecycleAuthorizeRefusesExpiredRelease(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	w := authorizeStatus(f, v.Token)
	assertAPIStatus(t, w, 204)
	if w.Header().Get("X-Fserver-Cache-Control") != "public, no-cache" {
		t.Fatal(w.Header())
	}
	past := time.Now().Add(-time.Second)
	if _, err := f.a.s.setExpiry(v.Token, &past); err != nil {
		t.Fatal(err)
	}
	assertAPIStatus(t, authorizeStatus(f, v.Token), 404) // refused before the sweeper runs
	if _, err := f.a.s.info(v.Token); err != nil {
		t.Fatal("authorize must not delete:", err)
	}
	// Extending revives it.
	mcpView(t, f, "set_expiry", map[string]any{"token": v.Token, "expires_in_days": 1})
	assertAPIStatus(t, authorizeStatus(f, v.Token), 204)
}

func TestLifecycleSweepExpiredDeletesOnlyExpired(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	expired, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", map[string]any{"password": "visitor-password"}))
	future, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	never, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", map[string]any{"expires_in_days": 0}))
	past := time.Now().Add(-time.Minute)
	if _, err := f.a.s.setExpiry(expired.Token, &past); err != nil {
		t.Fatal(err)
	}

	n, err := f.a.sweepExpired(time.Now())
	if err != nil || n != 1 {
		t.Fatalf("swept %d, %v", n, err)
	}
	for name, dir := range map[string]string{"public": f.a.s.public} {
		if _, err := os.Lstat(filepath.Join(dir, expired.Token)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still has the expired release: %v", name, err)
		}
	}
	for _, p := range []string{filepath.Join(f.a.s.manifests, expired.Token+".json"), filepath.Join(f.a.s.policies, expired.Token+".json")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", p, err)
		}
	}
	for _, v := range []releaseView{future, never} {
		if _, err := f.a.s.info(v.Token); err != nil {
			t.Fatalf("kept release %s was deleted: %v", v.Token, err)
		}
	}
	// Nothing left to do; sweeping again deletes nothing.
	if n, err = f.a.sweepExpired(time.Now()); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
	// A far-future clock expires the dated release but never the 0-day one.
	if n, err = f.a.sweepExpired(time.Now().Add(3651 * 24 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("future sweep: %d %v", n, err)
	}
	if _, err = f.a.s.info(never.Token); err != nil {
		t.Fatal("a release without expiry was swept:", err)
	}
}

func TestLifecycleDeleteExpiredRechecksUnderLock(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	past := time.Now().Add(-time.Minute)
	if _, err := f.a.s.setExpiry(v.Token, &past); err != nil {
		t.Fatal(err)
	}
	// The sweeper listed it as expired, then the owner extended it.
	mcpView(t, f, "set_expiry", map[string]any{"token": v.Token, "expires_in_days": 30})
	deleted, err := f.a.s.deleteExpired(v.Token, time.Now())
	if err != nil || deleted {
		t.Fatalf("deleteExpired removed an extended release: %v %v", deleted, err)
	}
	if _, err = f.a.s.info(v.Token); err != nil {
		t.Fatal(err)
	}
	if deleted, err = f.a.s.deleteExpired(v.Token, time.Now().Add(31*24*time.Hour)); err != nil || !deleted {
		t.Fatalf("deleteExpired of an expired release: %v %v", deleted, err)
	}
	// Already gone: not an error for the sweeper's purposes? It reports the cause.
	if deleted, _ = f.a.s.deleteExpired(v.Token, time.Now()); deleted {
		t.Fatal("deleted twice")
	}
}

func TestLifecycleUpdateInPlace(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	first, _ := mcpView(t, f, "publish_files", fileArgs("hello.txt", "old bytes", map[string]any{"label": "keep me", "password": "visitor-password", "expires_in_days": 10}))
	if first.UpdatedAt != nil {
		t.Fatal("updated_at set on a new release")
	}
	time.Sleep(10 * time.Millisecond)

	// Omitted password, label and expiry are kept.
	up, _ := mcpView(t, f, "publish_files", fileArgs("hello.txt", "new bytes", map[string]any{"token": first.Token}))
	if up.Token != first.Token || up.URL != first.URL {
		t.Fatalf("token or URL changed: %s -> %s", first.URL, up.URL)
	}
	if !up.CreatedAt.Equal(first.CreatedAt) || up.UpdatedAt == nil || !up.UpdatedAt.After(first.CreatedAt) {
		t.Fatalf("created_at/updated_at: %+v", up.manifest)
	}
	if up.Label != "keep me" || !up.Protected || up.ExpiresAt == nil || !up.ExpiresAt.Equal(*first.ExpiresAt) {
		t.Fatalf("kept fields: %+v", up)
	}
	if !strings.Contains(up.Notice, "set_expiry") {
		t.Fatalf("update result has no notice: %q", up.Notice)
	}
	b, err := os.ReadFile(filepath.Join(currentContentDir(t, f.a.s, first.Token), "hello.txt"))
	if err != nil || string(b) != "new bytes" {
		t.Fatalf("bytes on disk: %q %v", b, err)
	}
	p, err := f.a.s.policy(first.Token)
	if err != nil || !p.Protected || !p.Check("viewer", "visitor-password") {
		t.Fatalf("policy must be kept: %+v %v", p, err)
	}
	if st, err := os.Stat(filepath.Join(f.a.s.public, first.Token)); err != nil || st.Mode().Perm() != 0555 {
		t.Fatalf("release dir not frozen: %v %v", st, err)
	}

	// A new password replaces the old one, a new label and expiry apply.
	now := time.Now()
	up, _ = mcpView(t, f, "publish_files", fileArgs("hello.txt", "third", map[string]any{"token": first.Token, "password": "another-password", "label": "renamed", "expires_in_days": 3}))
	if up.Label != "renamed" || !up.Protected {
		t.Fatalf("label/protected: %+v", up)
	}
	near(t, up.ExpiresAt, now.Add(3*24*time.Hour))
	p, _ = f.a.s.policy(first.Token)
	if p.Check("viewer", "visitor-password") || !p.Check("viewer", "another-password") {
		t.Fatal("password was not replaced")
	}

	// expires_in_days 0 on an update removes the expiry.
	up, _ = mcpView(t, f, "publish_files", fileArgs("hello.txt", "fourth", map[string]any{"token": first.Token, "expires_in_days": 0}))
	if up.ExpiresAt != nil {
		t.Fatalf("0 must remove expiry on update: %+v", up.ExpiresAt)
	}
	if ms, err := f.a.s.list(); err != nil || len(ms) != 1 {
		t.Fatalf("updates must not create releases: %d %v", len(ms), err)
	}
	// Staging is clean after updates (the previous content is removed).
	left, _ := filepath.Glob(filepath.Join(f.a.s.staging, "release-*"))
	if len(left) != 0 {
		t.Fatalf("staging left behind: %v", left)
	}
}

func TestLifecycleUpdateRefusals(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))

	e := mcpRefused(t, f, "publish_files", fileArgs("a.txt", "b", map[string]any{"token": "AAAAAAAAAAAAAAAAAAAAAA"}))
	if e.Error != "release not found" || e.Hint == "" {
		t.Fatalf("unknown token: %+v", e)
	}
	// A 22-character token that is not base64url passes the MCP schema? It must not pass the core.
	w := postRelease(t, f, `{"token":"not a valid token!!!!!"}`, tarFixture{"a.txt", 0, "b", nil})
	wantAPIError(t, w, 400, "invalid release token")
	w = postRelease(t, f, `{"token":"short"}`, tarFixture{"a.txt", 0, "b", nil})
	wantAPIError(t, w, 400, "invalid release token")
	w = postRelease(t, f, `{"token":"AAAAAAAAAAAAAAAAAAAAAA"}`, tarFixture{"a.txt", 0, "b", nil})
	wantAPIError(t, w, 404, "release not found")
	// begin_upload checks the target before minting a ticket.
	w = f.do("POST", "/_api/v1/uploads", mustJSON(t, map[string]any{"size": 1, "sha256": sumHex([]byte("x")), "idempotency_key": requestID(), "token": "AAAAAAAAAAAAAAAAAAAAAA"}), "application/json", "")
	wantAPIError(t, w, 404, "release not found")
	w = f.do("POST", "/_api/v1/uploads", mustJSON(t, map[string]any{"size": 1, "sha256": sumHex([]byte("x")), "idempotency_key": requestID(), "token": "bad!"}), "application/json", "")
	wantAPIError(t, w, 400, "invalid release token")

	ms, err := f.a.s.list()
	if err != nil || len(ms) != 1 || ms[0].Token != v.Token {
		t.Fatalf("a refused update published something: %v %v", ms, err)
	}
	b, _ := os.ReadFile(filepath.Join(f.a.s.public, v.Token, "a.txt"))
	if string(b) != "a" {
		t.Fatalf("content changed by refused update: %q", b)
	}
}

func TestLifecycleUpdateIdempotency(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	a, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "a", nil))
	b, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "b", nil))

	args := fileArgs("a.txt", "update", map[string]any{"token": a.Token})
	first, _ := mcpView(t, f, "publish_files", args)
	replay, _ := mcpView(t, f, "publish_files", args)
	if replay.Token != a.Token || replay.UpdatedAt == nil || !replay.UpdatedAt.Equal(*first.UpdatedAt) || replay.Notice == "" {
		t.Fatalf("replay differs: %+v vs %+v", replay, first)
	}
	// Same key, same bytes, different token: refused, nothing changed.
	other := fileArgs("a.txt", "update", map[string]any{"token": b.Token, "idempotency_key": args["idempotency_key"]})
	e := mcpRefused(t, f, "publish_files", other)
	if e.Error != "idempotency key was used with a different body" || e.Hint == "" {
		t.Fatalf("different token: %+v", e)
	}
	// ...and a different expires_in_days is a different body too.
	diff := fileArgs("a.txt", "update", map[string]any{"token": a.Token, "idempotency_key": args["idempotency_key"], "expires_in_days": 1})
	if e = mcpRefused(t, f, "publish_files", diff); e.Error != "idempotency key was used with a different body" {
		t.Fatalf("different expiry: %+v", e)
	}
	got, err := os.ReadFile(filepath.Join(f.a.s.public, b.Token, "a.txt"))
	if err != nil || string(got) != "b" {
		t.Fatalf("other release changed: %q %v", got, err)
	}
	if ms, _ := f.a.s.list(); len(ms) != 2 {
		t.Fatalf("release count %d", len(ms))
	}
}

func currentContentDir(t *testing.T, s *store, token string) string {
	t.Helper()
	m, err := s.info(token)
	if err != nil {
		t.Fatal(err)
	}
	return s.releaseDir(m)
}

func TestLifecycleUpdateRevisionFailureKeepsOldContent(t *testing.T) {
	f := testAPI(t)
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "old", map[string]any{"label": "first"}))
	container := filepath.Join(f.a.s.public, v.Token)
	if err := os.Chmod(container, 0755); err != nil {
		t.Fatal(err)
	}
	// A corrupt revision parent must fail closed without touching live bytes.
	if err := os.WriteFile(filepath.Join(container, ".revisions"), nil, 0444); err != nil {
		t.Fatal(err)
	}
	e := mcpRefused(t, f, "publish_files", fileArgs("a.txt", "new", map[string]any{"token": v.Token, "label": "second"}))
	if e.Hint == "" || strings.Contains(e.Error, f.a.s.root) {
		t.Fatalf("error: %+v", e)
	}
	b, err := os.ReadFile(filepath.Join(container, "a.txt"))
	if err != nil || string(b) != "old" {
		t.Fatalf("old content lost: %q %v", b, err)
	}
	m, err := f.a.s.info(v.Token)
	if err != nil || m.Label != "first" || m.UpdatedAt != nil || m.Revision != "" {
		t.Fatalf("manifest changed: %+v %v", m, err)
	}
	if st, err := os.Stat(container); err != nil || st.Mode().Perm() != 0555 {
		t.Fatalf("not frozen: %v %v", st, err)
	}
}

func TestLifecycleUpdateSingleFileToSite(t *testing.T) {
	f := testAPI(t)
	v, _ := mcpView(t, f, "publish_files", fileArgs("name.txt", "single", nil))
	if !strings.HasSuffix(v.URL, "/"+v.Token+"/name.txt") || v.OriginalFilename != "name.txt" {
		t.Fatalf("single file release: %+v", v)
	}
	site := map[string]any{"token": v.Token, "idempotency_key": requestID(), "files": []map[string]any{
		{"path": "index.html", "text": "<h1>hi</h1>"}, {"path": "style.css", "text": "body{}"}}}
	up, _ := mcpView(t, f, "publish_files", site)
	if up.Token != v.Token || !strings.HasSuffix(up.URL, "/"+v.Token+"/") || up.OriginalFilename != "" || up.Files != 2 {
		t.Fatalf("site update: %+v", up)
	}
	if _, err := os.Stat(filepath.Join(f.a.s.public, v.Token, "name.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old file still present: %v", err)
	}
	// And back to a single file: the URL names the file again.
	back, _ := mcpView(t, f, "publish_files", fileArgs("other.txt", "x", map[string]any{"token": v.Token}))
	if !strings.HasSuffix(back.URL, "/"+v.Token+"/other.txt") {
		t.Fatalf("back to single: %s", back.URL)
	}
}

func TestLifecycleListReleasesTotals(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 60 })
	a, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "12345", map[string]any{"expires_in_days": 3}))
	b, _ := mcpView(t, f, "publish_files", fileArgs("b.txt", "1234567", map[string]any{"expires_in_days": 30}))
	c, _ := mcpView(t, f, "publish_files", fileArgs("c.txt", "123", map[string]any{"expires_in_days": 0}))
	d, _ := mcpView(t, f, "publish_files", fileArgs("d.txt", "1", nil))
	past := time.Now().Add(-time.Hour) // expired, not yet swept: still counted, and expiring
	if _, err := f.a.s.setExpiry(d.Token, &past); err != nil {
		t.Fatal(err)
	}

	type listing struct {
		Releases []releaseView `json:"releases"`
		Count    int           `json:"count"`
		Total    int64         `json:"total_bytes"`
		Trunc    bool          `json:"truncated"`
		Expiring int           `json:"expiring_within_7_days"`
	}
	check := func(raw []byte) {
		t.Helper()
		var l listing
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("list_releases is not an object: %.300s (%v)", raw, err)
		}
		if l.Count != 4 || len(l.Releases) != 4 || l.Total != 5+7+3+1 || l.Trunc || l.Expiring != 2 {
			t.Fatalf("totals: %+v", l)
		}
		if !strings.Contains(string(raw), `"truncated":false`) {
			t.Fatalf("truncated must be present: %.300s", raw)
		}
		seen := map[string]bool{}
		for _, r := range l.Releases {
			seen[r.Token] = true
			if r.Notice != "" {
				t.Fatal("list views carry no notice")
			}
		}
		if !seen[a.Token] || !seen[b.Token] || !seen[c.Token] || !seen[d.Token] {
			t.Fatalf("missing releases: %v", seen)
		}
	}
	check(mcpTool(t, f, "list_releases", map[string]any{}, false))
	w := f.do("GET", "/_api/v1/releases", nil, "", "")
	assertAPIStatus(t, w, 200)
	check(w.Body.Bytes())

	empty := testAPI(t)
	if raw := mcpTool(t, empty, "list_releases", map[string]any{}, false); !strings.Contains(string(raw), `"releases":[]`) || !strings.Contains(string(raw), `"count":0`) {
		t.Fatalf("empty listing: %s", raw)
	}
}

func TestLifecycleListReleasesTruncates(t *testing.T) {
	f := testAPI(t)
	s := f.a.s
	const total = mcpListMax + 5
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < total; i++ {
		tok := fmt.Sprintf("%022d", i)
		m := manifest{Token: tok, URL: s.baseURL + "/" + tok + "/", CreatedAt: base.Add(time.Duration(i) * time.Second), Files: 1, Bytes: 2}
		if err := os.Mkdir(filepath.Join(s.public, tok), 0555); err != nil {
			t.Fatal(err)
		}
		if err := s.writeManifest(m); err != nil {
			t.Fatal(err)
		}
		if err := writePrivateJSON(filepath.Join(s.policies, tok+".json"), accessPolicy{UpdatedAt: base}); err != nil {
			t.Fatal(err)
		}
	}
	w := f.do("GET", "/_api/v1/releases", nil, "", "")
	assertAPIStatus(t, w, 200)
	var l struct {
		Releases []releaseView `json:"releases"`
		Count    int           `json:"count"`
		Total    int64         `json:"total_bytes"`
		Trunc    bool          `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if l.Count != total || len(l.Releases) != mcpListMax || !l.Trunc || l.Total != 2*total {
		t.Fatalf("count=%d shown=%d truncated=%v total=%d", l.Count, len(l.Releases), l.Trunc, l.Total)
	}
	if l.Releases[0].Token != fmt.Sprintf("%022d", total-1) {
		t.Fatalf("not newest first: %s", l.Releases[0].Token)
	}
}

func TestDiskReportForLargestUploads(t *testing.T) {
	const bsize = 4096
	cfg := apiConfig{MinFreeBytes: 1 << 20, MaxUploadBytes: 1 << 30, MaxExtractBytes: 1 << 20, MaxEntries: 100}
	a := &apiServer{cfg: cfg}
	inline := cfg
	inline.MaxUploadBytes, inline.MaxExtractBytes = 1<<20, 1<<20
	st := syscall.Statfs_t{Bsize: bsize, Blocks: 1 << 20, Bavail: (cfg.MinFreeBytes + 100<<20) / bsize, Files: 1000000, Ffree: 900000}

	r := diskReportFor(st, cfg, inline)
	if r.FreeBytes != st.Bavail*bsize || r.TotalBytes != st.Blocks*bsize || r.ReserveBytes != cfg.MinFreeBytes || r.AvailableBytes != 100<<20 {
		t.Fatalf("basic fields: %+v", r)
	}
	if r.FreeInodes == nil || *r.FreeInodes != st.Ffree {
		t.Fatalf("free_inodes: %v", r.FreeInodes)
	}
	fits := func(n int64) bool {
		limits := a.uploadLimits(n, true)
		return apiDiskAvailable(st, limits, uploadReserve(n, limits))
	}
	if f := r.LargestFileUploadBytes; f != 20<<20 || !fits(f) || fits(f+1) {
		t.Fatalf("largest file %d: fits=%v fits+1=%v", f, fits(f), fits(f+1))
	}
	// Archive: size + 4*max_extract above the reserve.
	if want := int64(100<<20 - 4*cfg.MaxExtractBytes); r.LargestArchiveUploadBytes != want {
		t.Fatalf("largest archive %d want %d", r.LargestArchiveUploadBytes, want)
	}
	if !r.InlinePublishOK {
		t.Fatal("inline publish should fit")
	}

	// Capped by the upload maximum.
	capped := cfg
	capped.MaxUploadBytes = 10 << 20
	r = diskReportFor(st, capped, inline)
	if r.LargestFileUploadBytes != 10<<20 || r.LargestArchiveUploadBytes != 10<<20 {
		t.Fatalf("cap: %+v", r)
	}

	// Barely above the reserve: nothing fits, no underflow.
	tight := st
	tight.Bavail = cfg.MinFreeBytes / bsize
	r = diskReportFor(tight, cfg, inline)
	if r.AvailableBytes != 0 || r.LargestFileUploadBytes != 0 || r.LargestArchiveUploadBytes != 0 || r.InlinePublishOK {
		t.Fatalf("tight: %+v", r)
	}
	below := st
	below.Bavail = 1
	if r = diskReportFor(below, cfg, inline); r.AvailableBytes != 0 || r.LargestFileUploadBytes != 0 {
		t.Fatalf("below reserve: %+v", r)
	}
}

func TestDiskReportForInodesAndInvalidBlockSize(t *testing.T) {
	cfg := apiConfig{MinFreeBytes: 1 << 20, MaxUploadBytes: 1 << 30, MaxExtractBytes: 1 << 20, MaxEntries: 100}
	inline := cfg
	inline.MaxUploadBytes = 1 << 20
	good := syscall.Statfs_t{Bsize: 4096, Blocks: 1 << 20, Bavail: 1 << 18, Files: 1000000, Ffree: 900000}

	dynamic := good
	dynamic.Files, dynamic.Ffree = 0, 0
	r := diskReportFor(dynamic, cfg, inline)
	if r.FreeInodes != nil || r.LargestFileUploadBytes == 0 || !r.InlinePublishOK {
		t.Fatalf("no fixed inode budget: %+v", r)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"free_inodes":null`) {
		t.Fatalf("free_inodes must serialize as null: %s", raw)
	}

	low := good
	low.Ffree = minFreeInodes // below minFreeInodes + 5*MaxEntries + 32
	r = diskReportFor(low, cfg, inline)
	if r.FreeInodes == nil || *r.FreeInodes != low.Ffree || r.FreeBytes == 0 {
		t.Fatalf("inode figures: %+v", r)
	}
	if r.LargestFileUploadBytes != 0 || r.LargestArchiveUploadBytes != 0 || r.InlinePublishOK {
		t.Fatalf("below the inode reserve nothing fits: %+v", r)
	}
	if r.AvailableBytes == 0 {
		t.Fatal("available_bytes is about bytes only")
	}

	r = diskReportFor(syscall.Statfs_t{}, cfg, inline)
	if r.FreeBytes != 0 || r.LargestFileUploadBytes != 0 || r.InlinePublishOK || r.ReserveBytes != cfg.MinFreeBytes {
		t.Fatalf("zero block size: %+v", r)
	}
}

func TestDiskReportInServerInfo(t *testing.T) {
	f := lifecycleAPI(t, func(c *apiConfig) { c.DefaultExpiryDays = 45 })
	var info struct {
		DefaultExpiryDays int `json:"default_expiry_days"`
		Disk              *struct {
			FreeBytes    uint64          `json:"free_bytes"`
			TotalBytes   uint64          `json:"total_bytes"`
			FreeInodes   json.RawMessage `json:"free_inodes"`
			Reserve      uint64          `json:"reserve_bytes"`
			Available    uint64          `json:"available_bytes"`
			LargestFile  int64           `json:"largest_file_upload_bytes"`
			LargestArch  int64           `json:"largest_archive_upload_bytes"`
			InlinePublic *bool           `json:"inline_publish_ok"`
		} `json:"disk"`
	}
	raw := mcpTool(t, f, "server_info", map[string]any{}, false)
	if err := json.Unmarshal(raw, &info); err != nil || info.Disk == nil || info.DefaultExpiryDays != 45 {
		t.Fatalf("server_info: %s (%v)", raw, err)
	}
	d := info.Disk
	if d.FreeBytes == 0 || d.TotalBytes < d.FreeBytes || d.Reserve != f.a.cfg.MinFreeBytes || len(d.FreeInodes) == 0 || d.InlinePublic == nil {
		t.Fatalf("disk: %s", raw)
	}
	if d.LargestFile < 0 || d.LargestFile > f.a.cfg.MaxUploadBytes || d.Available > d.FreeBytes {
		t.Fatalf("disk figures: %s", raw)
	}
	// The same report is on the internal route.
	w := f.do("GET", "/_api/v1/me", nil, "", "")
	assertAPIStatus(t, w, 200)
	if !bytes.Contains(w.Body.Bytes(), []byte(`"disk":{`)) || !bytes.Contains(w.Body.Bytes(), []byte(`"default_expiry_days":45`)) {
		t.Fatalf("me: %s", w.Body)
	}
}

func TestEnvExpiryDays(t *testing.T) {
	const name = "FSERVER_DEFAULT_EXPIRY_DAYS"
	for _, c := range []struct {
		value string
		want  int
		fails bool
	}{
		{"", 60, false}, {"0", 0, false}, {"1", 1, false}, {"3650", 3650, false},
		{"-1", 0, true}, {"3651", 0, true}, {"x", 0, true}, {"1.5", 0, true}, {" 7", 0, true},
	} {
		t.Setenv(name, c.value)
		got, err := envExpiryDays(name)
		if c.fails {
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%q: want an error naming the variable, got %d %v", c.value, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %d %v, want %d", c.value, got, err, c.want)
		}
	}
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	if got, err := envExpiryDays(name); err != nil || got != 60 {
		t.Fatalf("unset: %d %v", got, err)
	}
}

// TestLifecycleURLFollowsBaseURL publishes a single file and a website under
// base URL A, restarts on base URL B, and checks every result that carries a
// release URL reports B: the url stored in the manifest is never read.
func TestLifecycleURLFollowsBaseURL(t *testing.T) {
	const oldBase, newBase = "https://old.example.test", "https://new.example.test"
	f := testAPI(t)
	oldStore, err := newStore(f.a.s.root, oldBase)
	if err != nil {
		t.Fatal(err)
	}
	if f.a, err = newAPIServer(oldStore, f.tokens, f.a.cfg); err != nil {
		t.Fatal(err)
	}
	single, _ := mcpView(t, f, "publish_files", fileArgs("hello.txt", "single", nil))
	site, _ := mcpView(t, f, "publish_files", map[string]any{"idempotency_key": requestID(), "files": []map[string]any{
		{"path": "index.html", "text": "<h1>hi</h1>"}, {"path": "style.css", "text": "body{}"}}})
	if single.URL != oldBase+"/"+single.Token+"/hello.txt" || site.URL != oldBase+"/"+site.Token+"/" {
		t.Fatalf("publish under A: %s %s", single.URL, site.URL)
	}

	// Restart with the new domain; the manifests on disk still say A.
	newS, err := newStore(f.a.s.root, newBase)
	if err != nil {
		t.Fatal(err)
	}
	if f.a, err = newAPIServer(newS, f.tokens, f.a.cfg); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(newS.manifests, single.Token+".json")); err != nil || !strings.Contains(string(raw), oldBase) {
		t.Fatalf("test needs a manifest that still stores A: %v", err)
	}
	want := map[string]string{single.Token: newBase + "/" + single.Token + "/hello.txt", site.Token: newBase + "/" + site.Token + "/"}
	check := func(what, token, got string) {
		t.Helper()
		if got != want[token] {
			t.Fatalf("%s: url %q, want %q", what, got, want[token])
		}
	}

	var l struct {
		Releases []releaseView `json:"releases"`
	}
	if err := json.Unmarshal(mcpTool(t, f, "list_releases", map[string]any{}, false), &l); err != nil || len(l.Releases) != 2 {
		t.Fatalf("list_releases: %+v %v", l, err)
	}
	for _, v := range l.Releases {
		check("list_releases", v.Token, v.URL)
	}
	for token := range want {
		v, _ := mcpView(t, f, "release_info", map[string]any{"token": token})
		check("release_info", token, v.URL)
		v, _ = mcpView(t, f, "set_expiry", map[string]any{"token": token, "expires_in_days": 5})
		check("set_expiry", token, v.URL)
		v, _ = mcpView(t, f, "set_password", map[string]any{"token": token, "password": "visitor-password"})
		check("set_password", token, v.URL)
		var reset struct {
			Release releaseView `json:"release"`
		}
		if err := json.Unmarshal(mcpTool(t, f, "reset_password", map[string]any{"token": token}, false), &reset); err != nil {
			t.Fatal(err)
		}
		check("reset_password", token, reset.Release.URL)
		v, _ = mcpView(t, f, "remove_password", map[string]any{"token": token})
		check("remove_password", token, v.URL)
		w := f.do("GET", "/_api/v1/releases/"+token, nil, "", "")
		assertAPIStatus(t, w, 200)
		var api releaseView
		if err := json.Unmarshal(w.Body.Bytes(), &api); err != nil {
			t.Fatal(err)
		}
		check("GET /_api/v1/releases/TOKEN", token, api.URL)
	}

	// An update in place reports B for both shapes, and rewrites the manifest.
	up, _ := mcpView(t, f, "publish_files", fileArgs("hello.txt", "new bytes", map[string]any{"token": single.Token}))
	check("update single file", single.Token, up.URL)
	up, _ = mcpView(t, f, "publish_files", map[string]any{"token": site.Token, "idempotency_key": requestID(), "files": []map[string]any{
		{"path": "index.html", "text": "<h1>new</h1>"}, {"path": "style.css", "text": "body{}"}}})
	check("update website", site.Token, up.URL)
	if raw, err := os.ReadFile(filepath.Join(newS.manifests, site.Token+".json")); err != nil || strings.Contains(string(raw), oldBase) {
		t.Fatalf("updated manifest still stores A: %s %v", raw, err)
	}

	// begin_upload's upload_url is on B too.
	if v := beginUpload(t, f, beginArgs([]byte("x"), map[string]any{"filename": "x.txt"})); !strings.HasPrefix(v.UploadURL, newBase+"/") {
		t.Fatalf("upload_url %q", v.UploadURL)
	}
}

func TestLifecycleRevisionsArePrivateFrozenAndReclaimed(t *testing.T) {
	f := testAPI(t)
	v, _ := mcpView(t, f, "publish_files", fileArgs("a.txt", "old", nil))
	roots := []string{filepath.Join(f.a.s.public, v.Token)}
	var previous string
	for _, content := range []string{"second", "third"} {
		up, raw := mcpView(t, f, "publish_files", fileArgs("a.txt", content, map[string]any{"token": v.Token}))
		if up.Revision != "" || strings.Contains(raw, `"revision"`) {
			t.Fatal("private revision leaked")
		}
		m, err := f.a.s.info(v.Token)
		if err != nil || !validToken(m.Revision) || m.Revision == previous {
			t.Fatalf("revision: %+v %v", m, err)
		}
		dir := f.a.s.releaseDir(m)
		got, err := os.ReadFile(filepath.Join(dir, "a.txt"))
		if err != nil || string(got) != content {
			t.Fatalf("content: %q %v", got, err)
		}
		for _, root := range roots {
			if _, err := os.Stat(filepath.Join(root, "a.txt")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("old root still serves content: %v", err)
			}
		}
		roots = append(roots, dir)
		for p := dir; p != f.a.s.public; p = filepath.Dir(p) {
			st, err := os.Stat(p)
			if err != nil || st.Mode().Perm() != 0555 {
				t.Fatalf("revision directory not frozen: %s %v %v", p, st, err)
			}
		}
		previous = m.Revision
	}
	revisions, err := os.ReadDir(filepath.Join(f.a.s.public, v.Token, ".revisions"))
	if err != nil || len(revisions) != 1 {
		t.Fatalf("old revisions survived: %d %v", len(revisions), err)
	}
	if _, err := f.a.s.deleteRelease(v.Token); err != nil {
		t.Fatal(err)
	}
	for _, root := range roots {
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revision survived deletion: %v", err)
		}
	}
}
