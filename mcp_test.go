package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func mcpPost(t *testing.T, f apiFixture, method string, params any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(b))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-06-18")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	return w
}

func mcpTool(t *testing.T, f apiFixture, name string, args any, failed bool) json.RawMessage {
	t.Helper()
	w := mcpPost(t, f, "tools/call", map[string]any{"name": name, "arguments": args})
	if w.Code != 200 {
		t.Fatalf("MCP status %d: %.2000s", w.Code, w.Body)
	}
	var result struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Error) > 0 || len(result.Result.Content) != 1 || result.Result.IsError != failed {
		t.Fatalf("unexpected MCP result: %.2000s (%v)", w.Body, err)
	}
	return json.RawMessage(result.Result.Content[0].Text)
}

func mcpPublishFile(t *testing.T, f apiFixture, args map[string]any) releaseView {
	t.Helper()
	raw := mcpTool(t, f, "publish_files", args, false)
	var v releaseView
	if err := json.Unmarshal(raw, &v); err != nil || !validToken(v.Token) {
		t.Fatalf("invalid release %s (%v)", raw, err)
	}
	return v
}

func TestMCPInitializeDiscoveryAndAnnotations(t *testing.T) {
	f := testAPI(t)
	w := mcpPost(t, f, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "integration", "version": "1"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"serverInfo"`) || w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("initialize: %d %s", w.Code, w.Body)
	}
	w = mcpPost(t, f, "tools/list", map[string]any{})
	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
				Annotations struct {
					ReadOnly    bool `json:"readOnlyHint"`
					Destructive bool `json:"destructiveHint"`
					OpenWorld   bool `json:"openWorldHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list.Result.Tools) != 10 {
		t.Fatalf("tools: %d %s (%v)", w.Code, w.Body, err)
	}
	for _, tool := range list.Result.Tools {
		wantOpenWorld := tool.Name == "publish_files" || tool.Name == "publish_archive" || tool.Name == "remove_password"
		if tool.Annotations.OpenWorld != wantOpenWorld || tool.InputSchema["additionalProperties"] != false {
			t.Fatalf("unsafe schema/annotation: %+v", tool)
		}
		if tool.Name == "download_release" && !tool.Annotations.ReadOnly || tool.Name == "remove_password" && !tool.Annotations.Destructive {
			t.Fatalf("incorrect annotation: %+v", tool)
		}
		if strings.Contains(string(mustJSON(t, tool.InputSchema)), "bearer") {
			t.Fatal("bearer argument exposed")
		}
	}
	raw := mcpTool(t, f, "server_info", map[string]any{}, false)
	if !bytes.Contains(raw, []byte(`"namespace":"default"`)) || bytes.Contains(raw, []byte(f.key)) {
		t.Fatalf("server_info: %s", raw)
	}
}

type mcpTestTransport func(*http.Request) (*http.Response, error)

func (f mcpTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMCPOfficialSDKClientAndRevocation(t *testing.T) {
	f := testAPI(t)
	server := httptest.NewServer(f.a)
	defer server.Close()
	clientHTTP := &http.Client{Transport: mcpTestTransport(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+f.key)
		return http.DefaultTransport.RoundTrip(r)
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "SDK integration", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: clientHTTP, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 10 {
		t.Fatalf("SDK ListTools: %v", err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "server_info", Arguments: map[string]any{}})
	if err != nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("SDK CallTool: %v", err)
	}
	if err = f.tokens.Revoke("test agent"); err != nil {
		t.Fatal(err)
	}
	if _, err = session.ListTools(ctx, nil); err == nil {
		t.Fatal("revoked credential still usable with SDK client")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMCPSharedManagementAndIdempotency(t *testing.T) {
	f := testAPI(t)
	args := map[string]any{"label": "text document", "password": "visitor-password", "idempotency_key": requestID(), "files": []map[string]any{{"path": "hello.txt", "text": "hello world"}}}
	v := mcpPublishFile(t, f, args)
	if !v.Protected || v.OriginalFilename != "hello.txt" || !strings.HasPrefix(v.URL, f.a.s.baseURL+"/") {
		t.Fatalf("release: %+v", v)
	}
	replay := mcpPublishFile(t, f, args)
	if replay.Token != v.Token {
		t.Fatal("idempotency not shared")
	}
	args["label"] = "changed"
	mcpTool(t, f, "publish_files", args, true)
	base := map[string]any{"token": v.Token}
	mcpTool(t, f, "release_info", base, false)
	mcpTool(t, f, "list_releases", map[string]any{}, false)
	download := mcpTool(t, f, "download_release", base, false)
	var d struct {
		Inline bool   `json:"inline"`
		Data   string `json:"content_base64"`
	}
	if json.Unmarshal(download, &d) != nil || !d.Inline || d.Data != base64.StdEncoding.EncodeToString([]byte("hello world")) {
		t.Fatalf("download: %s", download)
	}
	mcpTool(t, f, "set_password", map[string]any{"token": v.Token, "password": "replacement-password"}, false)
	p, _ := f.a.s.policy(v.Token)
	if !p.Check("viewer", "replacement-password") {
		t.Fatal("MCP did not update REST policy")
	}
	reset := mcpTool(t, f, "reset_password", base, false)
	var resetResult struct {
		Password string `json:"password"`
	}
	_ = json.Unmarshal(reset, &resetResult)
	p, _ = f.a.s.policy(v.Token)
	if len(resetResult.Password) < 24 || !p.Check("viewer", resetResult.Password) {
		t.Fatal("reset password not usable")
	}
	mcpTool(t, f, "remove_password", base, false)
	p, _ = f.a.s.policy(v.Token)
	if p.Protected {
		t.Fatal("password not removed")
	}
	mcpTool(t, f, "delete_release", base, false)
	if _, err := f.a.s.info(v.Token); err == nil {
		t.Fatal("delete not shared")
	}
	mcpTool(t, f, "release_info", base, true)
}

func TestMCPPublishFilesArchiveAndZIP(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, map[string]any{"spa": true, "idempotency_key": requestID(), "files": []map[string]any{
		{"path": "index.html", "text": "<h1>hello</h1>"}, {"path": "assets/logo.svg", "content_base64": base64.StdEncoding.EncodeToString([]byte("<svg/>"))}}})
	if !v.SPA || v.Files != 2 || v.OriginalFilename != "" {
		t.Fatalf("%+v", v)
	}
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	file, _ := zw.Create("wrapped/index.html")
	_, _ = io.WriteString(file, "<h1>ZIP</h1>")
	_ = zw.Close()
	for _, archive := range [][]byte{
		fixtureTar(t, tarFixture{"bundle/index.html", 0, "<h1>tar</h1>", nil}),
		fixtureGzip(t, fixtureTar(t, tarFixture{"bundle/index.html", 0, "<h1>gzip</h1>", nil})),
		z.Bytes(),
	} {
		result := mcpTool(t, f, "publish_archive", map[string]any{"archive_base64": base64.StdEncoding.EncodeToString(archive), "idempotency_key": requestID()}, false)
		var release releaseView
		if json.Unmarshal(result, &release) != nil || !validToken(release.Token) {
			t.Fatalf("invalid archive publish: %s", result)
		}
	}
}

type mcpUnreadBody struct{ reads int }

func (b *mcpUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *mcpUnreadBody) Close() error             { return nil }

func TestMCPAuthenticationOriginAdmissionAndBodyLimits(t *testing.T) {
	f := testAPI(t)
	for _, tc := range []struct {
		key, origin, method, target string
		length                      int64
		status                      int
		busy                        bool
	}{
		{"wrong", "", "POST", "/mcp", -1, 401, false},
		{f.key, "https://evil.invalid", "POST", "/mcp", -1, 403, false},
		{f.key, "null", "POST", "/mcp", -1, 403, false},
		{f.key, "", "GET", "/mcp", -1, 405, false},
		{f.key, "", "DELETE", "/mcp", -1, 405, false},
		{f.key, "", "POST", "/mcp", -1, 429, true},
		{f.key, "", "POST", "/mcp", f.a.mcpBodyLimit() + 1, 413, false},
		{f.key, "", "POST", "/mcp?key=bad", -1, 404, false},
	} {
		body := new(mcpUnreadBody)
		r := httptest.NewRequest(tc.method, tc.target, nil)
		r.Body, r.ContentLength = body, tc.length
		r.Header.Set("Authorization", "Bearer "+tc.key)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.busy {
			f.a.mcpAdmission <- struct{}{}
		}
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		if tc.busy {
			<-f.a.mcpAdmission
		}
		if w.Code != tc.status || body.reads != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%+v: status=%d reads=%d body=%s", tc, w.Code, body.reads, w.Body)
		}
	}
	// Exact configured public origin is accepted (never wildcard or prefix).
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	r.Header.Set("Authorization", "Bearer "+f.key)
	public, _ := url.Parse(f.a.s.baseURL)
	r.Header.Set("Origin", public.Scheme+"://"+public.Host)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("same origin: %d %s", w.Code, w.Body)
	}
	if err := f.tokens.Revoke("test agent"); err != nil {
		t.Fatal(err)
	}
	w = mcpPost(t, f, "tools/list", map[string]any{})
	if w.Code != 401 {
		t.Fatalf("revocation: %d %s", w.Code, w.Body)
	}
}

func TestMCPRejectsUnsafeAndUnboundedArguments(t *testing.T) {
	f := testAPI(t)
	for _, args := range []map[string]any{
		{"files": []map[string]any{{"path": "ok.txt", "text": "ok"}}},
		{"idempotency_key": requestID(), "files": []map[string]any{{"path": "../escape.txt", "text": "bad"}}},
		{"idempotency_key": requestID(), "files": []map[string]any{{"path": ".env", "text": "bad"}}},
		{"idempotency_key": requestID(), "files": []map[string]any{{"path": "ok.txt", "text": "x", "content_base64": "eA=="}}},
		{"idempotency_key": requestID(), "files": []map[string]any{{"path": "ok.txt", "content_base64": "%%%="}}},
		{"idempotency_key": requestID(), "files": []map[string]any{{"path": "ok.txt", "text": "x"}}, "bearer": "never-accepted"},
	} {
		mcpTool(t, f, "publish_files", args, true)
	}
	mcpTool(t, f, "publish_archive", map[string]any{"idempotency_key": requestID(), "archive_base64": base64.StdEncoding.EncodeToString(make([]byte, f.a.cfg.MaxUploadBytes+1))}, true)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`))
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("batch accepted")
	}
	// Exercise chunked/unknown-length body cap, not only Content-Length.
	r = httptest.NewRequest("POST", "/mcp", io.MultiReader(strings.NewReader("{"), io.LimitReader(zeroReader{}, f.a.mcpBodyLimit()+1)))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w = httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("streamed limit: %d %.500s", w.Code, w.Body)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestMCPDownloadFallbackAndCaptureBound(t *testing.T) {
	f := testAPI(t)
	f.a.cfg.MaxExtractBytes = 2 << 20
	v := publishAPI(t, f, `{}`, tarFixture{"large.pdf", 0, strings.Repeat("x", mcpInlineBytes+1), nil})
	raw := mcpTool(t, f, "download_release", map[string]any{"token": v.Token}, false)
	var fallback struct {
		URL    string `json:"download_url"`
		Auth   bool   `json:"requires_bearer_auth"`
		Inline bool   `json:"inline"`
	}
	if json.Unmarshal(raw, &fallback) != nil || !fallback.Auth || fallback.Inline || !strings.HasSuffix(fallback.URL, "/"+v.Token+"/download") || strings.Contains(string(raw), f.key) {
		t.Fatalf("bad fallback %s", raw)
	}
	w := &mcpCapture{header: make(http.Header), limit: 8}
	if _, err := w.Write([]byte("123456789")); err == nil || !w.overflow || w.body.Len() > 8 {
		t.Fatal("capture retained excess output")
	}
}

func TestMCPConcurrentAdmissionBeforeRead(t *testing.T) {
	f := testAPI(t)
	f.a.mcpAdmission <- struct{}{}
	defer func() { <-f.a.mcpAdmission }()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			body := new(mcpUnreadBody)
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+f.key)
			r.Body = body
			w := httptest.NewRecorder()
			f.a.ServeHTTP(w, r)
			if w.Code != 429 || body.reads > 0 {
				t.Errorf("concurrent admission status=%d reads=%d", w.Code, body.reads)
			}
		})
	}
	wg.Wait()
}

func TestMCPRejectsDuplicateAliasedAndNestedArguments(t *testing.T) {
	for _, raw := range []string{
		`{"idempotency_key":"aaaaaaaaaaaaaaaa","idempotency_key":"bbbbbbbbbbbbbbbb"}`,
		`{"IDEMPOTENCY_KEY":"aaaaaaaaaaaaaaaa"}`,
		`{"idempotency_key":"aaaaaaaaaaaaaaaa","files":[{"path":"a.txt","path":"b.txt","text":"x"}]}`,
		`{"idempotency_key":"aaaaaaaaaaaaaaaa","files":[{"path":"a.txt","text":{"secret":"x"}}]}`,
		`{"idempotency_key":"aaaaaaaaaaaaaaaa","files":[{"path":"a.txt","TEXT":"x"}]}`,
		`null`,
		`{} {}`,
	} {
		var args mcpPublishArgs
		if err := mcpDecode(json.RawMessage(raw), &args); err == nil {
			t.Fatalf("accepted invalid input: %s", raw)
		}
	}
	var args mcpPublishArgs
	raw := `{"idempotency_key":"aaaaaaaaaaaaaaaa","files":[{"path":"a.txt","text":"quotes: \" and slash: \\ and braces: {} []"}]}`
	if err := mcpDecode(json.RawMessage(raw), &args); err != nil || len(args.Files) != 1 || args.Files[0].Text == nil {
		t.Fatalf("valid escaped contents rejected: %v", err)
	}
}

func TestMCPArrayCardinalityBoundBeforeAllocation(t *testing.T) {
	for _, element := range []string{"{}", "null"} {
		raw := json.RawMessage(`{"files":[` + strings.Repeat(element+",", mcpMaxFiles) + element + `]}`)
		var args mcpPublishArgs
		err := mcpDecode(raw, &args)
		if err == nil || element == "{}" && !errors.Is(err, errMCPArrayLimit) || args.Files != nil {
			t.Fatalf("cardinality bound must precede Unmarshal (%s): %v", element, err)
		}
	}
	// A compact body can fit millions of empty elements under the envelope
	// byte cap. It must retain no slice and do only <=5000 elements' work.
	raw := json.RawMessage(`{"files":[` + strings.Repeat("{},", 999999) + `{}]}`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var args mcpPublishArgs
	err := mcpDecode(raw, &args)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errMCPArrayLimit) || args.Files != nil {
		t.Fatalf("million-element input reached Unmarshal: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Fatalf("excess allocation before array rejection: %d", allocated)
	}
}

func TestMCPRejectsExplicitNullBeforePublicActivation(t *testing.T) {
	f := testAPI(t)
	archive := base64.StdEncoding.EncodeToString(fixtureTar(t, tarFixture{"hello.txt", 0, "fixture", nil}))
	for _, name := range []string{"publish_files", "publish_archive"} {
		for _, field := range []string{"password", "label", "spa"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				args := map[string]any{"idempotency_key": requestID(), field: nil}
				if name == "publish_files" {
					args["files"] = []map[string]any{{"path": "hello.txt", "text": "fixture"}}
				} else {
					args["archive_base64"] = archive
				}
				mcpTool(t, f, name, args, true)
				active, err := f.a.s.list()
				if err != nil || len(active) != 0 {
					t.Fatal("invalid nullable argument activated a release")
				}
			})
		}
	}
	for _, file := range []map[string]any{
		{"path": nil, "text": "fixture"},
		{"path": "hello.txt", "text": nil, "content_base64": "Zml4dHVyZQ=="},
		{"path": "hello.txt", "text": "fixture", "content_base64": nil},
	} {
		mcpTool(t, f, "publish_files", map[string]any{
			"idempotency_key": requestID(), "files": []map[string]any{file},
		}, true)
	}
	active, err := f.a.s.list()
	if err != nil || len(active) != 0 {
		t.Fatal("invalid nullable file content activated a release")
	}
	// Omitting a password is still the explicitly documented public mode.
	v := mcpPublishFile(t, f, map[string]any{"idempotency_key": requestID(),
		"files": []map[string]any{{"path": "hello.txt", "text": "fixture"}}})
	if v.Protected {
		t.Fatal("omitted password no longer publishes in documented public mode")
	}
}

func TestMCPProtocolStructuralBudgetBeforeSDK(t *testing.T) {
	for _, raw := range []string{
		`{"params":{"_meta":{"items":[` + strings.Repeat("null,", mcpMaxFiles) + `null]}}}`,
		strings.Repeat("[", mcpMaxJSONDepth+1) + `0` + strings.Repeat("]", mcpMaxJSONDepth+1),
		`{` + strings.Repeat(`"x":null,`, mcpMaxJSONItems+1) + `"end":null}`,
	} {
		if _, err := io.ReadAll(&mcpJSONBudgetReader{r: strings.NewReader(raw)}); err == nil {
			t.Fatal("structurally oversized protocol input accepted")
		}
	}
	// Quoted delimiters/commas and escapes do not consume the structural budget.
	raw := string(mustJSON(t, map[string]string{"text": strings.Repeat(`{},[]\"`, mcpMaxJSONItems+1)}))
	if _, err := io.ReadAll(&mcpJSONBudgetReader{r: strings.NewReader(raw)}); err != nil {
		t.Fatalf("ordinary string content charged as structure: %v", err)
	}
	f := testAPI(t)
	metadata := make([]any, mcpMaxFiles+1)
	w := mcpPost(t, f, "tools/list", map[string]any{"_meta": map[string]any{"items": metadata}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "array entry limit") {
		t.Fatalf("SDK metadata was not rejected before decode: %d %.500s", w.Code, w.Body)
	}
}

func TestMCPAuditDoesNotContainArgumentsOrCredentials(t *testing.T) {
	f := testAPI(t)
	log, err := os.CreateTemp(t.TempDir(), "audit-")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	previous := os.Stderr
	os.Stderr = log
	defer func() { os.Stderr = previous }()
	mcpPublishFile(t, f, map[string]any{"label": "PRIVATE_LABEL_SENTINEL", "password": "PRIVATE_PASSWORD_SENTINEL", "idempotency_key": requestID(),
		"files": []map[string]any{{"path": "hello.txt", "text": "PRIVATE_CONTENT_SENTINEL"}}})
	if _, err = log.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.key, "PRIVATE_LABEL_SENTINEL", "PRIVATE_PASSWORD_SENTINEL", "PRIVATE_CONTENT_SENTINEL"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("sensitive tool data appeared in audit")
		}
	}
	if !bytes.Contains(b, []byte(`"operation":"publish"`)) || !bytes.Contains(b, []byte(`"operation":"mcp"`)) {
		t.Fatal("shared API audits missing")
	}
}

func FuzzMCPDecode(f *testing.F) {
	for _, raw := range []string{`{}`, `{"files":[{"path":"a.txt","text":"hello"}],"idempotency_key":"aaaaaaaaaaaaaaaa"}`, `{"files":null}`, `{"files":[{},{}]}`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		var args mcpPublishArgs
		_ = mcpDecode(json.RawMessage(raw), &args)
	})
}

// Opt-in integration probe for the documented 100 MiB server-side request.
// Run separately in a constrained worker/container; normal race tests stay small.
func TestMCPLargeArchive(t *testing.T) {
	if os.Getenv("FSERVER_TEST_LARGE_MCP") != "1" {
		t.Skip("set FSERVER_TEST_LARGE_MCP=1 for 100 MiB memory probe")
	}
	f := testAPI(t)
	f.a.cfg.MaxUploadBytes = mcpMaxArchiveBytes
	f.a.cfg.MaxExtractBytes = mcpMaxArchiveBytes
	f.a.mcpHandler = f.a.newMCPHandler()
	// Exact 100 MiB tar: one regular file plus its 512-byte header and 1024-byte
	// trailer. This tests decoded size, not a tiny compressed stand-in.
	archive := fixtureTar(t, tarFixture{"large.pdf", 0, strings.Repeat("a", mcpMaxArchiveBytes-1536), nil})
	if len(archive) != mcpMaxArchiveBytes {
		t.Fatalf("probe archive size=%d", len(archive))
	}
	mcpTool(t, f, "publish_archive", map[string]any{"idempotency_key": requestID(), "archive_base64": base64.StdEncoding.EncodeToString(archive)}, false)
}
