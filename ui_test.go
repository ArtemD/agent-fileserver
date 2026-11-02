package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type uiResourceEntry struct {
	URI      string         `json:"uri"`
	Name     string         `json:"name"`
	MIMEType string         `json:"mimeType"`
	Meta     map[string]any `json:"_meta"`
}

var uiAllURIs = []string{uiReleaseURI, uiReleasesURI, uiUploadURI}

var uiMarkers = []string{"__FSERVER_BASE_URL__", "/*FSERVER:BRIDGE*/", "/*FSERVER:BASE_CSS*/"}

func uiListResources(t *testing.T, f apiFixture) map[string]uiResourceEntry {
	t.Helper()
	w := mcpPost(t, f, "resources/list", map[string]any{})
	var list struct {
		Result struct {
			Resources []uiResourceEntry `json:"resources"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list.Error) > 0 {
		t.Fatalf("resources/list: %d %.1000s (%v)", w.Code, w.Body, err)
	}
	out := map[string]uiResourceEntry{}
	for _, r := range list.Result.Resources {
		out[r.URI] = r
	}
	if len(out) != len(list.Result.Resources) {
		t.Fatalf("duplicate resource URIs: %+v", list.Result.Resources)
	}
	return out
}

func uiOrigin(t *testing.T, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		t.Fatalf("base URL %q: %v", base, err)
	}
	return u.Scheme + "://" + u.Host
}

// uiMetaUI returns _meta.ui as a map, failing when it is absent.
func uiMetaUI(t *testing.T, meta map[string]any) map[string]any {
	t.Helper()
	ui, ok := meta["ui"].(map[string]any)
	if !ok {
		t.Fatalf("_meta.ui missing: %v", meta)
	}
	return ui
}

func TestUIResourcesList(t *testing.T) {
	f := testAPI(t)
	if !strings.Contains(f.a.s.baseURL, "/") || uiOrigin(t, f.a.s.baseURL) == f.a.s.baseURL {
		t.Fatalf("fixture base URL %q should carry a path so the origin trimming is exercised", f.a.s.baseURL)
	}
	got := uiListResources(t, f)
	var uris []string
	for uri := range got {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	want := append([]string(nil), uiAllURIs...)
	sort.Strings(want)
	if !reflect.DeepEqual(uris, want) {
		t.Fatalf("resources: %v, want exactly %v", uris, want)
	}
	for uri, r := range got {
		if r.MIMEType != "text/html;profile=mcp-app" || r.Name == "" {
			t.Fatalf("%s: %+v", uri, r)
		}
		ui := uiMetaUI(t, r.Meta)
		if ui["prefersBorder"] != true {
			t.Fatalf("%s prefersBorder: %v", uri, ui)
		}
		csp, hasCSP := ui["csp"].(map[string]any)
		if uri == uiUploadURI {
			domains, _ := csp["connectDomains"].([]any)
			if !hasCSP || len(domains) != 1 || domains[0] != uiOrigin(t, f.a.s.baseURL) {
				t.Fatalf("upload connectDomains: %v, want [%s]", csp, uiOrigin(t, f.a.s.baseURL))
			}
			if strings.Contains(domains[0].(string), "/base") {
				t.Fatalf("connectDomains carries a path: %v", domains)
			}
			continue
		}
		if hasCSP {
			if _, ok := csp["connectDomains"]; ok {
				t.Fatalf("%s must not get connectDomains: %v", uri, csp)
			}
		}
	}
}

func TestUIResourcesRead(t *testing.T) {
	f := testAPI(t)
	listed := uiListResources(t, f)
	quotedBase, _ := json.Marshal(f.a.s.baseURL)
	for _, uri := range uiAllURIs {
		w := mcpPost(t, f, "resources/read", map[string]any{"uri": uri})
		var read struct {
			Result struct {
				Contents []struct {
					URI      string         `json:"uri"`
					MIMEType string         `json:"mimeType"`
					Text     string         `json:"text"`
					Blob     string         `json:"blob"`
					Meta     map[string]any `json:"_meta"`
				} `json:"contents"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil || w.Code != 200 || len(read.Error) > 0 || len(read.Result.Contents) != 1 {
			t.Fatalf("%s: %d %.500s (%v)", uri, w.Code, w.Body, err)
		}
		c := read.Result.Contents[0]
		if c.URI != uri || c.MIMEType != "text/html;profile=mcp-app" || c.Blob != "" {
			t.Fatalf("%s content: uri=%q mime=%q", uri, c.URI, c.MIMEType)
		}
		if !reflect.DeepEqual(c.Meta, listed[uri].Meta) || len(c.Meta) == 0 {
			t.Fatalf("%s: read _meta %v differs from list _meta %v", uri, c.Meta, listed[uri].Meta)
		}
		if !strings.Contains(c.Text, "window.fserver") {
			t.Fatalf("%s: bridge not inlined", uri)
		}
		if !strings.Contains(c.Text, string(quotedBase)) {
			t.Fatalf("%s: base URL %s not inlined", uri, quotedBase)
		}
		for _, m := range uiMarkers {
			if strings.Contains(c.Text, m) {
				t.Fatalf("%s: leftover marker %q", uri, m)
			}
		}
	}
	// An unknown ui:// resource (or a path under the right host) is an error.
	for _, uri := range []string{"ui://agent-fileserver/nope.html", "ui://other/release.html", "ui://agent-fileserver/"} {
		w := mcpPost(t, f, "resources/read", map[string]any{"uri": uri})
		if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) || bytes.Contains(w.Body.Bytes(), []byte(`"contents"`)) {
			t.Fatalf("%s: %d %.500s", uri, w.Code, w.Body)
		}
	}
}

func TestUIComposePanelEscapesHostileBase(t *testing.T) {
	scriptOpen := regexp.MustCompile(`(?i)<script[\s>]`)
	hostile := "https://x.example\"</script><script>alert(1)</script> '\\&"
	for _, file := range []string{"release.html", "releases.html", "upload.html"} {
		clean, err := uiComposePanel(file, "https://files.example.com/base")
		if err != nil {
			t.Fatal(file, err)
		}
		page, err := uiComposePanel(file, hostile)
		if err != nil {
			t.Fatal(file, err)
		}
		if strings.Contains(page, "</script><script>alert") || strings.Contains(page, "alert(1)</script>") {
			t.Fatalf("%s: hostile base broke out of the script", file)
		}
		for _, p := range []string{page, clean} {
			if n, m := len(scriptOpen.FindAllString(p, -1)), strings.Count(strings.ToLower(p), "</script>"); n == 0 || n != m {
				t.Fatalf("%s: %d <script> tags but %d </script>", file, n, m)
			}
			for _, marker := range uiMarkers {
				if strings.Contains(p, marker) {
					t.Fatalf("%s: leftover marker %q", file, marker)
				}
			}
		}
		if strings.Contains(page, " ") {
			t.Fatalf("%s: raw U+2028 left in the script", file)
		}
		// The hostile value appears only as a JSON string (quotes escaped).
		quoted, _ := json.Marshal(hostile)
		if !strings.Contains(page, string(quoted)) {
			t.Fatalf("%s: base URL not inlined as a JSON string", file)
		}
	}
	if _, err := uiComposePanel("missing.html", "https://files.example.com"); err == nil {
		t.Fatal("a missing panel file composed")
	}
}

func TestUIToolsCarryPanelLinks(t *testing.T) {
	f := testAPI(t)
	w := mcpPost(t, f, "tools/list", map[string]any{})
	var list struct {
		Result struct {
			Tools []struct {
				Name string         `json:"name"`
				Meta map[string]any `json:"_meta"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 {
		t.Fatalf("tools/list: %d %.500s (%v)", w.Code, w.Body, err)
	}
	want := map[string]string{
		"publish_files": uiReleaseURI, "publish_archive": uiReleaseURI, "release_info": uiReleaseURI,
		"set_expiry": uiReleaseURI, "set_password": uiReleaseURI, "remove_password": uiReleaseURI,
		"list_releases": uiReleasesURI, "upload_from_computer": uiUploadURI,
		"begin_upload": "", "delete_release": "", "download_release": "", "reset_password": "", "server_info": "",
	}
	seen := map[string]bool{}
	for _, tool := range list.Result.Tools {
		uri, ok := want[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool %s", tool.Name)
		}
		seen[tool.Name] = true
		if uri == "" {
			if _, has := tool.Meta["ui"]; has {
				t.Fatalf("%s must not link a panel: %v", tool.Name, tool.Meta)
			}
			if _, has := tool.Meta["ui/resourceUri"]; has {
				t.Fatalf("%s must not link a panel: %v", tool.Name, tool.Meta)
			}
			continue
		}
		if got := uiMetaUI(t, tool.Meta)["resourceUri"]; got != uri {
			t.Fatalf("%s _meta.ui.resourceUri = %v, want %s", tool.Name, got, uri)
		}
		if tool.Meta["ui/resourceUri"] != uri {
			t.Fatalf("%s flat ui/resourceUri = %v, want %s", tool.Name, tool.Meta["ui/resourceUri"], uri)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("tools seen %v, want %d", seen, len(want))
	}
}

func uiUploadFrom(t *testing.T, f apiFixture, args any) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(mcpTool(t, f, "upload_from_computer", args, false), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// uiUploadRefused asserts upload_from_computer is refused with this error
// string and a next-step hint, as a tool error result (not a protocol error).
func uiUploadRefused(t *testing.T, f apiFixture, args any, wantError string) {
	t.Helper()
	w := mcpPost(t, f, "tools/call", map[string]any{"name": "upload_from_computer", "arguments": args})
	var res struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("%v: %.500s", args, w.Body)
	}
	if len(res.Error) > 0 || !res.Result.IsError || len(res.Result.Content) != 1 {
		t.Fatalf("%v accepted: %.500s", args, w.Body)
	}
	var body apiErrorBody
	if err := json.Unmarshal([]byte(res.Result.Content[0].Text), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != wantError || strings.TrimSpace(body.Hint) == "" {
		t.Fatalf("%v: error %q hint %q, want %q with a hint", args, body.Error, body.Hint, wantError)
	}
}

func TestUploadFromComputer(t *testing.T) {
	f := testAPI(t)
	existing := mcpPublishFile(t, f, map[string]any{"idempotency_key": requestID(), "expires_in_days": 5,
		"files": []map[string]any{{"path": "index.html", "text": "<h1>x</h1>"}}})

	for name, args := range map[string]map[string]any{
		"empty":    {},
		"label":    {"label": "report for Anna"},
		"spa":      {"spa": true},
		"password": {"password": "correct horse battery"},
		"expiry":   {"expires_in_days": 30},
		"forever":  {"expires_in_days": 0},
		"maximum":  {"expires_in_days": 3650},
		"update":   {"token": existing.Token, "label": "again"},
		"all":      {"label": "x", "spa": true, "password": "correct horse", "expires_in_days": 7, "token": existing.Token},
	} {
		t.Run("valid "+name, func(t *testing.T) {
			out := uiUploadFrom(t, f, args)
			if out["status"] == "" || out["status"] == nil || out["max_bytes"] != float64(f.a.cfg.MaxUploadBytes) {
				t.Fatalf("result: %v", out)
			}
			if next, _ := out["next"].(string); !strings.Contains(next, "begin_upload") {
				t.Fatalf("next: %v", out["next"])
			}
		})
	}

	secretToken := strings.Repeat("a", 22)
	for name, tc := range map[string]struct {
		args any
		want string
	}{
		"long label":      {map[string]any{"label": strings.Repeat("l", 201)}, "invalid upload_from_computer arguments"},
		"control label":   {map[string]any{"label": "a\x01b"}, "invalid upload_from_computer arguments"},
		"unknown field":   {map[string]any{"bearer": "x"}, "invalid upload_from_computer arguments"},
		"idempotency key": {map[string]any{"idempotency_key": requestID()}, "invalid upload_from_computer arguments"},
		"not an object":   {[]any{1}, "invalid upload_from_computer arguments"},
		"short password":  {map[string]any{"password": "short"}, "password must be 8 to 72 UTF-8 bytes without control characters"},
		"long password":   {map[string]any{"password": strings.Repeat("p", 73)}, "password must be 8 to 72 UTF-8 bytes without control characters"},
		"expiry too big":  {map[string]any{"expires_in_days": 3651}, "expires_in_days must be an integer from 0 to 3650"},
		"expiry negative": {map[string]any{"expires_in_days": -1}, "expires_in_days must be an integer from 0 to 3650"},
		"malformed token": {map[string]any{"token": "short"}, "invalid release token"},
		"unknown token":   {map[string]any{"token": secretToken}, "release not found"},
	} {
		t.Run("refused "+name, func(t *testing.T) { uiUploadRefused(t, f, tc.args, tc.want) })
	}

	// The tool only validates and instructs: nothing is published, no ticket
	// is minted, and the existing release is untouched.
	if len(f.a.tickets) != 0 {
		t.Fatalf("%d tickets minted by upload_from_computer", len(f.a.tickets))
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(mcpTool(t, f, "list_releases", map[string]any{}, false), &list); err != nil || list.Count != 1 {
		t.Fatalf("list_releases count %d (%v), want only the fixture release", list.Count, err)
	}
	var info releaseView
	if err := json.Unmarshal(mcpTool(t, f, "release_info", map[string]any{"token": existing.Token}, false), &info); err != nil ||
		info.Label != existing.Label || info.Protected || info.SPA {
		t.Fatalf("existing release changed: %+v (%v)", info, err)
	}
}

func TestUploadFromComputerIsReadOnlyAndClosedWorld(t *testing.T) {
	f := testAPI(t)
	w := mcpPost(t, f, "tools/list", map[string]any{})
	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
				Annotations struct {
					ReadOnly    bool  `json:"readOnlyHint"`
					Destructive *bool `json:"destructiveHint"`
					OpenWorld   *bool `json:"openWorldHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, tool := range list.Result.Tools {
		if tool.Name != "upload_from_computer" {
			continue
		}
		a := tool.Annotations
		if !a.ReadOnly || a.Destructive == nil || *a.Destructive || a.OpenWorld == nil || *a.OpenWorld {
			t.Fatalf("annotations: %+v", a)
		}
		props, _ := tool.InputSchema["properties"].(map[string]any)
		for _, k := range []string{"label", "spa", "password", "token", "expires_in_days"} {
			if _, ok := props[k]; !ok {
				t.Fatalf("schema lacks %s: %v", k, props)
			}
		}
		for _, k := range []string{"idempotency_key", "files", "filename", "size", "sha256"} {
			if _, ok := props[k]; ok {
				t.Fatalf("schema must not offer %s", k)
			}
		}
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatalf("schema allows extra properties: %v", tool.InputSchema)
		}
		return
	}
	t.Fatal("upload_from_computer is not listed")
}

const uiForeignOrigin = "https://abc.claudemcpcontent.com"

func TestUploadCORS(t *testing.T) {
	f := testAPI(t)
	data := siteZIP(t)
	n := int64(len(data))
	v := beginUpload(t, f, beginArgs(data, nil))
	ticket := v.Headers["Authorization"]

	// Preflight: no ticket needed, none consumed, never with credentials.
	for _, origin := range []string{uiForeignOrigin, "null", "https://evil.example"} {
		for _, auth := range [][]string{nil, {ticket}} {
			w := f.put(nil, putOpts{method: "OPTIONS", auth: auth, length: 0, extra: map[string]string{"Origin": origin,
				"Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "authorization, content-type"}})
			h := w.Header()
			if w.Code != 204 || w.Body.Len() != 0 || h.Get("Access-Control-Allow-Origin") != "*" ||
				h.Get("Access-Control-Allow-Methods") != "PUT" || h.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" ||
				h.Get("Access-Control-Max-Age") == "" || h.Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("preflight from %q: %d %v", origin, w.Code, h)
			}
		}
	}
	// The ticket survived every preflight and works exactly once, cross-origin.
	w := f.put(bytes.NewReader(data), putOpts{auth: []string{ticket}, length: n, extra: map[string]string{"Origin": uiForeignOrigin}})
	view := releaseOf(t, w)
	h := w.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Access-Control-Allow-Credentials") != "" ||
		!strings.Contains(h.Get("Access-Control-Expose-Headers"), "X-Request-ID") {
		t.Fatalf("cross-origin PUT headers: %v", h)
	}
	if view.Files != 2 {
		t.Fatalf("release: %+v", view)
	}
	noSpool(t, f)

	// Errors are readable by the panel too: the same ticket is now spent, so
	// both a missing and a used ticket answer 401 with the CORS headers.
	for name, auth := range map[string][]string{"no ticket": nil, "used ticket": {ticket}, "management key": {"Bearer " + f.key}} {
		w := f.put(bytes.NewReader(data), putOpts{auth: auth, length: n, extra: map[string]string{"Origin": uiForeignOrigin}})
		assertAPIStatus(t, w, 401)
		if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("%s: 401 lacks CORS headers: %v", name, w.Header())
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: 401 lacks WWW-Authenticate", name)
		}
	}
	// A wrong method answers 405 with the CORS headers and the new Allow.
	w = f.put(nil, putOpts{method: "GET", length: 0, extra: map[string]string{"Origin": uiForeignOrigin}})
	assertAPIStatus(t, w, 405)
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Allow") != "PUT, OPTIONS" {
		t.Fatalf("405 headers: %v", w.Header())
	}
	// Only the exact path takes part, preflight included.
	w = f.put(nil, putOpts{method: "OPTIONS", target: "/_upload?x=1", length: 0, extra: map[string]string{"Origin": uiForeignOrigin}})
	assertAPIStatus(t, w, 404)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("non-canonical path got CORS headers: %v", w.Header())
	}

	// A management key is still not an upload credential, whatever the Origin,
	// and a ticket is still not a management credential.
	if got := len(f.a.tickets); got != 0 {
		t.Fatalf("%d tickets left", got)
	}
}

func TestMCPStillRefusesForeignOrigins(t *testing.T) {
	f := testAPI(t)
	for _, origin := range []string{uiForeignOrigin, "null", "https://evil.example"} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.Header.Set("Authorization", "Bearer "+f.key)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("/mcp from %q: %d %v", origin, w.Code, w.Header())
		}
	}
	// A preflight to /mcp is not answered with CORS headers either.
	r := httptest.NewRequest("OPTIONS", "/mcp", nil)
	r.Header.Set("Origin", uiForeignOrigin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code == 204 {
		t.Fatalf("/mcp preflight: %d %v", w.Code, w.Header())
	}
}
