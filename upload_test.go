package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type uploadTicketView struct {
	UploadURL string            `json:"upload_url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt string            `json:"expires_at"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256"`
	Command   string            `json:"command"`
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// beginArgs returns valid begin_upload arguments for data with a fresh key.
func beginArgs(data []byte, extra map[string]any) map[string]any {
	args := map[string]any{"size": len(data), "sha256": sumHex(data), "idempotency_key": requestID()}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

func beginUpload(t *testing.T, f apiFixture, args map[string]any) uploadTicketView {
	t.Helper()
	raw := mcpTool(t, f, "begin_upload", args, false)
	var v uploadTicketView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("begin_upload result %s: %v", raw, err)
	}
	return v
}

// beginFails asserts begin_upload is refused, whether by the schema layer
// (JSON-RPC error) or by the tool (isError result), and returns the body.
func beginFails(t *testing.T, f apiFixture, args any) string {
	t.Helper()
	w := mcpPost(t, f, "tools/call", map[string]any{"name": "begin_upload", "arguments": args})
	if w.Code != 200 && w.Code != 400 {
		t.Fatalf("status %d: %.500s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"isError":true`) && !strings.Contains(body, `"error":{`) {
		t.Fatalf("begin_upload accepted %v: %.500s", args, body)
	}
	if strings.Contains(body, "upl_") {
		t.Fatalf("refused begin_upload minted a ticket: %.500s", body)
	}
	return body
}

type putOpts struct {
	auth     []string // Authorization header values; nil means none
	extra    map[string]string
	target   string
	method   string
	length   int64 // -2 = leave as the reader gives it
	clientIP string
}

func (f apiFixture) put(body io.Reader, o putOpts) *httptest.ResponseRecorder {
	if o.target == "" {
		o.target = "/_upload"
	}
	if o.method == "" {
		o.method = "PUT"
	}
	r := httptest.NewRequest(o.method, o.target, body)
	if o.length != -2 {
		r.ContentLength = o.length
	}
	for _, v := range o.auth {
		r.Header.Add("Authorization", v)
	}
	for k, v := range o.extra {
		r.Header.Set(k, v)
	}
	if o.clientIP == "" {
		o.clientIP = "192.0.2.1"
	}
	r.Header.Set("X-Fserver-Client-IP", o.clientIP)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	return w
}

// putTicket sends data with the ticket's own Authorization header.
func putTicket(f apiFixture, v uploadTicketView, data []byte) *httptest.ResponseRecorder {
	return f.put(bytes.NewReader(data), putOpts{auth: []string{v.Headers["Authorization"]}, length: int64(len(data))})
}

func releaseOf(t *testing.T, w *httptest.ResponseRecorder) releaseView {
	t.Helper()
	assertAPIStatus(t, w, 201)
	var v releaseView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || !validToken(v.Token) {
		t.Fatalf("invalid release %s (%v)", w.Body, err)
	}
	return v
}

func noSpool(t *testing.T, f apiFixture) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(f.a.incoming, "api-upload-put-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("spool left behind: %v %v", left, err)
	}
}

func siteZIP(t *testing.T) []byte {
	t.Helper()
	return fixtureZIP(t, zipFile("index.html", "<h1>hi</h1>"), zipFile("style.css", "body{}"))
}

func TestBeginUploadResultShape(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	before := time.Now()
	v := beginUpload(t, f, beginArgs(data, nil))
	if !strings.HasSuffix(v.UploadURL, "/_upload") || !strings.HasPrefix(v.UploadURL, "https://") || v.Method != "PUT" {
		t.Fatalf("bad target: %+v", v)
	}
	if !regexp.MustCompile(`^Bearer upl_[A-Za-z0-9_-]{43}$`).MatchString(v.Headers["Authorization"]) || len(v.Headers) != 1 {
		t.Fatalf("bad headers: %v", v.Headers)
	}
	exp, err := time.Parse(time.RFC3339, v.ExpiresAt)
	if err != nil || exp.Before(before.Add(29*time.Minute)) || exp.After(time.Now().Add(31*time.Minute)) {
		t.Fatalf("expires_at %q (%v)", v.ExpiresAt, err)
	}
	if v.Size != int64(len(data)) || v.SHA256 != sumHex(data) {
		t.Fatalf("echoed size/sha: %+v", v)
	}
	if !strings.Contains(v.Command, "-T FILE") || !strings.Contains(v.Command, v.Headers["Authorization"]) || !strings.Contains(v.Command, v.UploadURL) {
		t.Fatalf("command: %s", v.Command)
	}
}

func TestBeginUploadArgumentValidation(t *testing.T) {
	f := testAPI(t)
	data := []byte("some bytes")
	good := func() map[string]any { return beginArgs(data, nil) }
	with := func(k string, v any) map[string]any { a := good(); a[k] = v; return a }
	without := func(k string) map[string]any { a := good(); delete(a, k); return a }
	cases := map[string]map[string]any{
		"uppercase sha":   with("sha256", strings.ToUpper(sumHex(data))),
		"short sha":       with("sha256", sumHex(data)[:63]),
		"non-hex sha":     with("sha256", strings.Repeat("g", 64)),
		"missing sha":     without("sha256"),
		"zero size":       with("size", 0),
		"negative size":   with("size", -1),
		"oversize":        with("size", f.a.cfg.MaxUploadBytes+1),
		"fractional size": with("size", 1.5),
		"missing size":    without("size"),
		"missing key":     without("idempotency_key"),
		"short key":       with("idempotency_key", "short"),
		"bad key chars":   with("idempotency_key", strings.Repeat("a", 15)+"!"),
		"dotenv":          with("filename", ".env"),
		"slash":           with("filename", "a/b"),
		"backslash":       with("filename", `a\b`),
		"php":             with("filename", "x.php"),
		"control char":    with("filename", "a\x01b"),
		"dot dot":         with("filename", ".."),
		"long filename":   with("filename", strings.Repeat("a", 256)),
		"spa with file":   with("filename", "a.bin"),
		"short password":  with("password", "short"),
		"long password":   with("password", strings.Repeat("p", 73)),
		"unknown field":   with("bearer", "x"),
		"null label":      with("label", nil),
		"null filename":   with("filename", nil),
		"null spa":        with("spa", nil),
		"long label":      with("label", strings.Repeat("l", 201)),
	}
	cases["spa with file"]["spa"] = true
	for name, args := range cases {
		t.Run(name, func(t *testing.T) { beginFails(t, f, args) })
	}
	if len(f.a.tickets) != 0 {
		t.Fatalf("%d tickets minted by invalid requests", len(f.a.tickets))
	}
	// The same arguments, valid, succeed.
	beginUpload(t, f, good())
}

func TestUploadArchivePublishes(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, map[string]any{"label": "site"}))
	rel := releaseOf(t, putTicket(f, v, data))
	if rel.Files != 2 || rel.Label != "site" || rel.Protected || rel.SPA {
		t.Fatalf("release: %+v", rel)
	}
	for name, want := range map[string]string{"index.html": "<h1>hi</h1>", "style.css": "body{}"} {
		got, err := os.ReadFile(filepath.Join(f.a.s.public, rel.Token, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	noSpool(t, f)
}

func TestUploadSingleFilePublishes(t *testing.T) {
	f := testAPI(t)
	data := []byte{0, 1, 2, 255, 254, 128, 'x'}
	v := beginUpload(t, f, beginArgs(data, map[string]any{"filename": "report.bin"}))
	rel := releaseOf(t, putTicket(f, v, data))
	if rel.OriginalFilename != "report.bin" || rel.Files != 1 || rel.Bytes != int64(len(data)) {
		t.Fatalf("release: %+v", rel)
	}
	got, err := os.ReadFile(filepath.Join(f.a.s.public, rel.Token, "report.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("bytes changed: %v", err)
	}
	if n := len(entries(t, filepath.Join(f.a.s.public, rel.Token))); n != 1 {
		t.Fatalf("%d entries in single-file release", n)
	}
	noSpool(t, f)
}

func TestUploadPasswordProtectsRelease(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, map[string]any{"password": "correct horse battery"}))
	rel := releaseOf(t, putTicket(f, v, data))
	if !rel.Protected {
		t.Fatalf("release not protected: %+v", rel)
	}
	p, err := f.a.s.policy(rel.Token)
	if err != nil || !p.Protected || !p.Check(rel.Username, "correct horse battery") || p.Check(rel.Username, "wrong password!") {
		t.Fatalf("policy: %+v %v", p, err)
	}
}

func TestUploadSPAArchive(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, map[string]any{"spa": true}))
	if rel := releaseOf(t, putTicket(f, v, data)); !rel.SPA {
		t.Fatalf("spa not set: %+v", rel)
	}
}

func TestUploadTicketSingleUseAndExpiry(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, nil))
	releaseOf(t, putTicket(f, v, data))
	w := putTicket(f, v, data)
	assertAPIStatus(t, w, 401)
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate=%q", w.Header().Get("WWW-Authenticate"))
	}
	// A failed attempt also consumes the ticket.
	v = beginUpload(t, f, beginArgs(data, nil))
	assertAPIStatus(t, f.put(strings.NewReader("short"), putOpts{auth: []string{v.Headers["Authorization"]}, length: 5}), 400)
	assertAPIStatus(t, putTicket(f, v, data), 401)

	// Expiry.
	v = beginUpload(t, f, beginArgs(data, nil))
	f.a.mu.Lock()
	for k, tk := range f.a.tickets {
		tk.expires = time.Now().Add(-time.Second)
		f.a.tickets[k] = tk
	}
	f.a.mu.Unlock()
	assertAPIStatus(t, putTicket(f, v, data), 401)
	noSpool(t, f)
}

func TestUploadPendingTicketCap(t *testing.T) {
	f := testAPI(t)
	data := []byte("pending")
	for i := 0; i < 8; i++ {
		beginUpload(t, f, beginArgs(data, nil))
	}
	body := beginFails(t, f, beginArgs(data, nil))
	if !strings.Contains(body, "too many pending") {
		t.Fatalf("unexpected refusal: %s", body)
	}
	// Expired tickets free their slots.
	f.a.mu.Lock()
	for k, tk := range f.a.tickets {
		tk.expires = time.Now().Add(-time.Second)
		f.a.tickets[k] = tk
	}
	f.a.mu.Unlock()
	beginUpload(t, f, beginArgs(data, nil))
}

func TestUploadRevokedKeyInvalidatesTicket(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, nil))
	if err := f.tokens.Revoke("test agent"); err != nil {
		t.Fatal(err)
	}
	assertAPIStatus(t, putTicket(f, v, data), 401)
	noSpool(t, f)
}

func TestUploadCredentialConfusion(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	body := func() io.Reader { return bytes.NewReader(data) }
	n := int64(len(data))
	assertAPIStatus(t, f.put(body(), putOpts{auth: []string{"Bearer " + f.key}, length: n}), 401)
	assertAPIStatus(t, f.put(body(), putOpts{extra: map[string]string{"X-Auth-Token": f.key}, length: n}), 401)
	assertAPIStatus(t, f.put(body(), putOpts{length: n}), 401)

	v := beginUpload(t, f, beginArgs(data, nil))
	ticket := v.Headers["Authorization"]
	// A ticket in X-Auth-Token does not work, and does not burn the ticket.
	assertAPIStatus(t, f.put(body(), putOpts{extra: map[string]string{"X-Auth-Token": strings.TrimPrefix(ticket, "Bearer ")}, length: n}), 401)
	// Two Authorization headers are refused.
	assertAPIStatus(t, f.put(body(), putOpts{auth: []string{ticket, ticket}, length: n}), 401)

	// The ticket is refused as a management credential.
	for _, h := range []map[string]string{{"Authorization": ticket}, {"X-Auth-Token": strings.TrimPrefix(ticket, "Bearer ")}} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		for k, val := range h {
			r.Header.Set(k, val)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("ticket accepted on /mcp: %d %s", w.Code, w.Body)
		}
	}
	// Refusals before the ticket is parsed (wrong header, duplicate headers)
	// must not consume it: it still works, exactly once.
	releaseOf(t, putTicket(f, v, data))
}

func TestUploadOriginMethodAndPath(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, nil))
	auth := []string{v.Headers["Authorization"]}
	n := int64(len(data))

	// CORS preflight from an MCP Apps iframe origin: answered without a
	// ticket and without consuming one; never with credentials.
	w := f.put(nil, putOpts{method: "OPTIONS", length: 0, extra: map[string]string{"Origin": "https://0123abcd.claudemcpcontent.com",
		"Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "authorization, content-type"}})
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Methods") != "PUT" ||
		w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	for _, m := range []string{"GET", "POST", "DELETE", "HEAD"} {
		w = f.put(nil, putOpts{auth: auth, method: m, length: 0})
		if m == "HEAD" {
			if w.Code != 405 {
				t.Fatalf("HEAD: %d", w.Code)
			}
		} else {
			assertAPIStatus(t, w, 405)
		}
		if w.Header().Get("Allow") != "PUT, OPTIONS" {
			t.Fatalf("%s Allow=%q", m, w.Header().Get("Allow"))
		}
	}
	for _, target := range []string{"/_upload?x=1", "/_upload?", "/_upload/", "/_upload//", "/_upload/../_upload", "/_Upload"} {
		w = f.put(bytes.NewReader(data), putOpts{auth: auth, length: n, target: target})
		if w.Code != 404 {
			t.Fatalf("%s: %d %s", target, w.Code, w.Body)
		}
	}
	// Any origin may present the ticket (the ticket is the credential), and
	// the ticket survived all of the above.
	w = f.put(bytes.NewReader(data), putOpts{auth: auth, length: n, extra: map[string]string{"Origin": "null"}})
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("cross-origin PUT headers: %v", w.Header())
	}
	releaseOf(t, w)
}

func TestUploadBodyChecks(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	type tc struct {
		name   string
		body   func() io.Reader
		length int64
		want   int
		args   map[string]any
		data   []byte // declared bytes; default data
	}
	longer := append(append([]byte{}, data...), "extra"...)
	shorter := data[:len(data)-3]
	garbage := bytes.Repeat([]byte("not an archive "), 10)
	other := append([]byte{}, data...)
	other[len(other)/2] ^= 0xff
	cases := []tc{
		{name: "content-length larger", body: func() io.Reader { return bytes.NewReader(longer) }, length: int64(len(longer)), want: 413},
		{name: "content-length smaller", body: func() io.Reader { return bytes.NewReader(shorter) }, length: int64(len(shorter)), want: 400},
		{name: "chunked shorter", body: func() io.Reader { return io.MultiReader(bytes.NewReader(shorter)) }, length: -1, want: 400},
		{name: "chunked longer", body: func() io.Reader { return io.MultiReader(bytes.NewReader(longer)) }, length: -1, want: 413},
		{name: "sha mismatch", body: func() io.Reader { return bytes.NewReader(other) }, length: int64(len(other)), want: 400},
		{name: "garbage archive", body: func() io.Reader { return bytes.NewReader(garbage) }, length: int64(len(garbage)), want: 400, data: garbage},
		{name: "single file sha mismatch", body: func() io.Reader { return bytes.NewReader(other) }, length: int64(len(other)), want: 400, args: map[string]any{"filename": "x.bin"}},
		{name: "single file chunked shorter", body: func() io.Reader { return io.MultiReader(bytes.NewReader(shorter)) }, length: -1, want: 400, args: map[string]any{"filename": "x.bin"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := c.data
			if d == nil {
				d = data
			}
			v := beginUpload(t, f, beginArgs(d, c.args))
			w := f.put(c.body(), putOpts{auth: []string{v.Headers["Authorization"]}, length: c.length})
			assertAPIStatus(t, w, c.want)
			noSpool(t, f)
			if len(entries(t, f.a.s.public)) != 0 {
				t.Fatalf("failed upload published something")
			}
		})
	}
}

func TestUploadIdempotency(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	key := requestID()
	v1 := beginUpload(t, f, beginArgs(data, map[string]any{"idempotency_key": key}))
	r1 := releaseOf(t, putTicket(f, v1, data))
	v2 := beginUpload(t, f, beginArgs(data, map[string]any{"idempotency_key": key}))
	r2 := releaseOf(t, putTicket(f, v2, data))
	if r1.Token != r2.Token {
		t.Fatalf("retry published a second release: %s vs %s", r1.Token, r2.Token)
	}
	if n := len(entries(t, f.a.s.public)); n != 1 {
		t.Fatalf("%d releases", n)
	}
	different := fixtureZIP(t, zipFile("index.html", "<h1>different</h1>"))
	v3 := beginUpload(t, f, beginArgs(different, map[string]any{"idempotency_key": key}))
	assertAPIStatus(t, putTicket(f, v3, different), 409)
	noSpool(t, f)
}

func TestUploadOneAtATime(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, nil))
	f.a.uploadSlot <- struct{}{}
	assertAPIStatus(t, putTicket(f, v, data), 429)
	<-f.a.uploadSlot
	// The ticket was consumed by the busy attempt.
	assertAPIStatus(t, putTicket(f, v, data), 401)
	v = beginUpload(t, f, beginArgs(data, nil))
	releaseOf(t, putTicket(f, v, data))
	if len(f.a.uploadSlot) != 0 {
		t.Fatal("upload slot not released")
	}
}

func TestUploadAuthFailureRateLimit(t *testing.T) {
	f := testAPI(t)
	bad := "Bearer upl_" + strings.Repeat("A", 43)
	send := func(ip string) int {
		return f.put(strings.NewReader("x"), putOpts{auth: []string{bad}, length: 1, clientIP: ip}).Code
	}
	for i := 0; i < 10; i++ {
		if c := send("192.0.2.77"); c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := send("192.0.2.77"); c != 429 {
		t.Fatalf("11th bad ticket: %d", c)
	}
	if c := send("192.0.2.78"); c != 401 {
		t.Fatalf("other client IP affected: %d", c)
	}
}

func TestUploadServerInfoLimits(t *testing.T) {
	f := testAPI(t)
	info := func() (limits, upload map[string]float64) {
		var v struct {
			Limits map[string]float64 `json:"limits"`
			Upload map[string]float64 `json:"upload"`
		}
		raw := mcpTool(t, f, "server_info", map[string]any{}, false)
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v.Limits, v.Upload
	}
	limits, upload := info()
	if limits["max_upload_bytes"] != 2<<20 || limits["max_extract_bytes"] != 1<<20 || limits["max_entries"] != 100 {
		t.Fatalf("limits: %v", limits)
	}
	want := map[string]float64{"max_bytes": 2 << 20, "max_extract_bytes": 1 << 20, "max_entries": 100, "ticket_seconds": 1800, "max_pending_tickets": 8}
	if len(upload) != len(want) {
		t.Fatalf("upload: %v", upload)
	}
	for k, v := range want {
		if upload[k] != v {
			t.Fatalf("upload %s=%v want %v", k, upload[k], v)
		}
	}
	// Large configuration: MCP caps apply to limits, not to upload.
	f.a.cfg.MaxUploadBytes, f.a.cfg.MaxExtractBytes, f.a.cfg.MaxEntries = 1<<30, 1<<30, 50000
	limits, upload = info()
	if limits["max_upload_bytes"] != 100<<20 || limits["max_extract_bytes"] != 100<<20 || limits["max_entries"] != 5000 {
		t.Fatalf("capped limits: %v", limits)
	}
	if upload["max_bytes"] != 1<<30 || upload["max_extract_bytes"] != 1<<30 || upload["max_entries"] != 50000 {
		t.Fatalf("upload: %v", upload)
	}
}

func TestMCPLimitsCaps(t *testing.T) {
	f := testAPI(t)
	f.a.cfg.MaxUploadBytes, f.a.cfg.MaxExtractBytes, f.a.cfg.MaxEntries = 1<<30, 1<<30, 50000
	l := f.a.mcpLimits()
	if l.MaxUploadBytes != 100<<20 || l.MaxExtractBytes != 100<<20 || l.MaxEntries != 5000 {
		t.Fatalf("large cfg: %+v", l)
	}
	f.a.cfg.MaxUploadBytes, f.a.cfg.MaxExtractBytes, f.a.cfg.MaxEntries = 5<<20, 6<<20, 7
	l = f.a.mcpLimits()
	if l.MaxUploadBytes != 5<<20 || l.MaxExtractBytes != 6<<20 || l.MaxEntries != 7 {
		t.Fatalf("small cfg: %+v", l)
	}
	if f.a.cfg.MaxUploadBytes != 5<<20 {
		t.Fatal("mcpLimits mutated the configuration")
	}
}

func TestNewAPIServerUploadDefaults(t *testing.T) {
	f := testAPI(t)
	a, err := newAPIServer(f.a.s, f.tokens, apiConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if a.cfg.MaxUploadBytes != 1<<30 || a.cfg.MaxExtractBytes != 1<<30 || a.cfg.MaxEntries != 50000 {
		t.Fatalf("defaults: %+v", a.cfg)
	}
}

func TestEnvPositive(t *testing.T) {
	const name = "FSERVER_TEST_ENV_POSITIVE"
	t.Setenv(name, "")
	if n, err := envPositive(name); n != 0 || err != nil {
		t.Fatalf("empty: %d %v", n, err)
	}
	for _, bad := range []string{"abc", "0", "-1", "1.5", " 5", "99999999999999999999"} {
		t.Setenv(name, bad)
		if n, err := envPositive(name); err == nil || n != 0 {
			t.Fatalf("%q accepted: %d", bad, n)
		}
	}
	t.Setenv(name, "1073741824")
	if n, err := envPositive(name); err != nil || n != 1<<30 {
		t.Fatalf("valid: %d %v", n, err)
	}
	os.Unsetenv(name)
	if n, err := envPositive(name); n != 0 || err != nil {
		t.Fatalf("unset: %d %v", n, err)
	}
}

func TestTokenStoreActive(t *testing.T) {
	f := testAPI(t)
	now := time.Now()
	id, err := f.tokens.Authenticate(f.key, now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.tokens.Active(id.ID, now) {
		t.Fatal("active key reported inactive")
	}
	if f.tokens.Active(strings.Repeat("0", 64), now) || f.tokens.Active("", now) {
		t.Fatal("unknown id reported active")
	}
	if f.tokens.Active(id.ID, now.Add(0)) != true {
		t.Fatal("unexpected")
	}
	if err = f.tokens.Revoke("test agent"); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Active(id.ID, now) {
		t.Fatal("revoked key reported active")
	}
	// Expiring keys.
	_, raw, err := f.tokens.Create("expiring", defaultAccount, 1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := f.tokens.Authenticate(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.tokens.Active(id2.ID, now) || f.tokens.Active(id2.ID, now.Add(48*time.Hour)) {
		t.Fatal("expiry not honoured")
	}
}

func TestUploadAuditDoesNotContainTicket(t *testing.T) {
	f := testAPI(t)
	log, err := os.CreateTemp(t.TempDir(), "audit-")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	previous := os.Stderr
	os.Stderr = log
	defer func() { os.Stderr = previous }()
	data := siteZIP(t)
	v := beginUpload(t, f, beginArgs(data, map[string]any{"password": "PRIVATE_PASSWORD_SENTINEL"}))
	ticket := strings.TrimPrefix(v.Headers["Authorization"], "Bearer ")
	releaseOf(t, putTicket(f, v, data))
	// A refused attempt with the (now used) ticket is audited too.
	assertAPIStatus(t, putTicket(f, v, data), 401)
	if _, err = log.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{ticket, f.key, "PRIVATE_PASSWORD_SENTINEL", sumHex(data)} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("sensitive upload data appeared in audit: %q", secret[:8])
		}
	}
	if !bytes.Contains(b, []byte(`"operation":"upload"`)) || !bytes.Contains(b, []byte(`"operation":"begin_upload"`)) {
		t.Fatalf("upload audits missing: %s", b)
	}
}

func TestUploadRoutesNotReachableAsInternalCore(t *testing.T) {
	f := testAPI(t)
	// The in-process begin_upload endpoint is not a public route.
	r := httptest.NewRequest("POST", "/_api/v1/uploads", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Code == 200 || w.Code == 201 {
		t.Fatalf("public /_api/v1/uploads: %d", w.Code)
	}
	// In-process, wrong method.
	assertAPIStatus(t, f.do("GET", "/_api/v1/uploads", nil, "", ""), 405)
}

// Issue #13: a lone index.html is a one-page site; its release URL is the
// root, which the static server already answers with the page. Other single
// files keep /TOKEN/NAME.
func TestSingleIndexHTMLReportsRootURL(t *testing.T) {
	f := testAPI(t)
	page := []byte("<!doctype html><title>t</title><p>hello</p>")
	v := beginUpload(t, f, beginArgs(page, map[string]any{"filename": "index.html"}))
	rel := releaseOf(t, putTicket(f, v, page))
	if rel.OriginalFilename != "index.html" || rel.Files != 1 || rel.URL != f.a.s.baseURL+"/"+rel.Token+"/" {
		t.Fatalf("upload release: %+v", rel)
	}
	got, err := os.ReadFile(filepath.Join(f.a.s.public, rel.Token, "index.html"))
	if err != nil || !bytes.Equal(got, page) {
		t.Fatalf("page changed: %v", err)
	}
	inline := mcpPublishFile(t, f, map[string]any{"idempotency_key": requestID(), "files": []map[string]any{{"path": "index.html", "text": string(page)}}})
	if inline.URL != f.a.s.baseURL+"/"+inline.Token+"/" {
		t.Fatalf("publish_files url %q", inline.URL)
	}
	for _, name := range []string{"Index.html", "index.htm", "page.html"} {
		other := mcpPublishFile(t, f, map[string]any{"idempotency_key": requestID(), "files": []map[string]any{{"path": name, "text": string(page)}}})
		if other.URL != f.a.s.baseURL+"/"+other.Token+"/"+name {
			t.Fatalf("%s url %q", name, other.URL)
		}
	}
}
