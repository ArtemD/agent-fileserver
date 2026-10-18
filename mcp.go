package main

// MCP is only a bounded protocol adapter. All management operations go back
// through ServeHTTP, including its authentication, audit, policy and publisher.
import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpMaxArchiveBytes = 100 << 20
	mcpJSONOverhead    = 6 << 20
	mcpMaxBodyBytes    = 140 << 20
	mcpInlineBytes     = 1 << 20
	mcpOutputBytes     = 2 << 20
	mcpMaxFiles        = 5000
	mcpMaxJSONItems    = 50000
	mcpMaxJSONDepth    = 64
)

var errMCPArrayLimit = errors.New("MCP array entry limit exceeded")

type mcpRequestKey struct{}

func (a *apiServer) mcpBodyLimit() int64 {
	n := min(a.cfg.MaxUploadBytes, int64(mcpMaxArchiveBytes))
	return min(int64(base64.StdEncoding.EncodedLen(int(n)))+mcpJSONOverhead, int64(mcpMaxBodyBytes))
}

func (a *apiServer) serveMCP(w http.ResponseWriter, r *http.Request, id string) {
	u, _ := url.Parse(a.s.baseURL)
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && origins[0] != u.Scheme+"://"+u.Host {
		apiError(w, 403, id, "origin not allowed")
		return
	}
	if r.Method != http.MethodPost {
		methodError(w, id, "POST")
		return
	}
	// Admission must precede SDK body reads, not just the publishing operation:
	// JSON parsing may retain several copies of a large base64 argument.
	select {
	case a.mcpAdmission <- struct{}{}:
		defer func() { <-a.mcpAdmission }()
	default:
		apiError(w, 429, id, "MCP busy; retry with the same arguments and idempotency key")
		return
	}
	if r.ContentLength > a.mcpBodyLimit() {
		apiError(w, 413, id, "MCP request exceeds encoded archive and JSON overhead limit")
		return
	}
	// Do not allow JSON-RPC batches to turn a single admitted POST into an
	// unbounded fan-out of expensive policy/password operations.
	r.Body = http.MaxBytesReader(w, r.Body, a.mcpBodyLimit())
	probe := bufio.NewReaderSize(&mcpJSONBudgetReader{r: r.Body}, 4096)
	for {
		b, err := probe.Peek(1)
		if err != nil {
			apiError(w, 400, id, "expected one JSON-RPC request object")
			return
		}
		if strings.ContainsRune(" \t\r\n", rune(b[0])) {
			_, _ = probe.ReadByte()
			continue
		}
		if b[0] != '{' {
			apiError(w, 400, id, "expected one JSON-RPC request object; batches are not supported")
			return
		}
		break
	}
	r.Body = &mcpReadCloser{Reader: probe, Closer: r.Body}
	r = r.WithContext(context.WithValue(r.Context(), mcpRequestKey{}, r))
	a.mcpHandler.ServeHTTP(w, r)
}

type mcpReadCloser struct {
	io.Reader
	io.Closer
}

// Bound dynamic protocol metadata BEFORE the SDK unmarshals it. A byte cap
// alone is insufficient: millions of tiny objects/nulls in _meta can expand
// into much larger Go maps/slices. Arguments get stricter typed checks below.
// This scanner never retains string contents or a second request-body copy;
// encoding/json in the SDK remains responsible for JSON syntax validation.
type mcpJSONBudgetReader struct {
	r                io.Reader
	inString, escape bool
	stack            [mcpMaxJSONDepth]struct {
		array bool
		items int
	}
	depth, items int
}

func (r *mcpJSONBudgetReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	for _, b := range p[:n] {
		if r.inString {
			if r.escape {
				r.escape = false
			} else if b == '\\' {
				r.escape = true
			} else if b == '"' {
				r.inString = false
			}
			continue
		}
		switch b {
		case '"':
			r.inString = true
		case '{', '[':
			if r.depth == len(r.stack) {
				return 0, errors.New("MCP JSON nesting limit exceeded")
			}
			r.stack[r.depth].array = b == '['
			r.stack[r.depth].items = 1
			r.depth++
			r.items++
		case '}', ']':
			if r.depth > 0 {
				r.depth--
			}
		case ',':
			r.items++
			if r.depth > 0 {
				frame := &r.stack[r.depth-1]
				frame.items++
				if frame.array && frame.items > mcpMaxFiles {
					return 0, errMCPArrayLimit
				}
			}
		}
		if r.items > mcpMaxJSONItems {
			return 0, errors.New("MCP JSON structural item limit exceeded")
		}
	}
	return n, err
}

func mcpSchema(properties map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func (a *apiServer) newMCPHandler() http.Handler {
	// Explicit discard loggers: SDK diagnostics can include attacker-controlled
	// protocol errors. Only the existing structured, body-free API audit is used.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := mcp.NewServer(&mcp.Implementation{Name: "agent-fileserver", Version: buildVersion}, &mcp.ServerOptions{Logger: logger,
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		Instructions: "Publish clean static files only. Never pass management bearer keys as tool arguments. Publish retries require the same explicit idempotency_key and bytes. Downloads are inline only, up to 1 MiB; this is not a client file-attachment guarantee."})
	str := func() map[string]any { return map[string]any{"type": "string"} }
	token := func() map[string]any { return map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]+$"} }
	publish := func() map[string]any {
		return map[string]any{"label": map[string]any{"type": "string", "maxLength": 200}, "spa": map[string]any{"type": "boolean"},
			"password":        map[string]any{"type": "string", "description": "Optional visitor password, 8..72 UTF-8 bytes; not a management API key."},
			"idempotency_key": map[string]any{"type": "string", "minLength": 16, "maxLength": 128, "pattern": "^[A-Za-z0-9_-]+$"}}
	}
	add := func(name, description string, schema any, readOnly, destructive, idempotent bool) {
		openWorld := name == "publish_files" || name == "publish_archive" || name == "remove_password"
		server.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: schema,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &destructive, IdempotentHint: idempotent, OpenWorldHint: &openWorld}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return a.mcpCall(ctx, name, req.Params.Arguments), nil
			})
	}
	add("server_info", "Management identity, namespace and limits.", mcpSchema(map[string]any{}), true, false, true)
	add("list_releases", "List releases, newest first; at most the newest 1,000.", mcpSchema(map[string]any{}), true, false, true)
	for _, name := range []string{"release_info", "download_release", "delete_release", "reset_password", "remove_password"} {
		description := map[string]string{
			"release_info":     "Read release metadata and visitor access policy.",
			"download_release": "Download at most 1 MiB inline as base64; larger releases are refused with an error.",
			"delete_release":   "Permanently delete a release.",
			"reset_password":   "Replace visitor password with a random password returned once. Treat the returned password as secret.",
			"remove_password":  "Remove visitor password protection, making the release PUBLIC ON THE INTERNET."}[name]
		add(name, description, mcpSchema(map[string]any{"token": token()}, "token"), name == "release_info" || name == "download_release", name == "delete_release" || name == "reset_password" || name == "remove_password", name != "reset_password")
	}
	add("set_password", "Replace the visitor password. Password is not a management bearer key.", mcpSchema(map[string]any{"token": token(), "password": str()}, "token", "password"), false, true, true)
	p := publish()
	p["archive_base64"] = map[string]any{"type": "string", "contentEncoding": "base64", "description": "Standard padded base64 ZIP, tar, or tar.gz archive; decoded limit is min(server limit, 100 MiB). JSON and base64 overhead are bounded."}
	add("publish_archive", "Publish a static ZIP/tar/tar.gz to the PUBLIC INTERNET by default unless a visitor password is supplied. Uses the shared safe publisher. Explicit caller idempotency_key required; reuse exact arguments on retry.", mcpSchema(p, "archive_base64", "idempotency_key"), false, false, true)
	p = publish()
	p["files"] = map[string]any{"type": "array", "minItems": 1, "maxItems": min(a.cfg.MaxEntries, mcpMaxFiles), "items": mcpSchema(map[string]any{
		"path": str(), "text": map[string]any{"type": "string", "description": "UTF-8 contents; specify exactly one of text or content_base64."},
		"content_base64": map[string]any{"type": "string", "contentEncoding": "base64"}}, "path")}
	add("publish_files", "Publish raw text/base64 files to the PUBLIC INTERNET by default unless a visitor password is supplied. Paths are relative, without dot components, links or secrets. One file publishes as a single download; multiple files form a website directory. Explicit idempotency_key required.", mcpSchema(p, "files", "idempotency_key"), false, false, true)
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, Logger: logger, MaxRequestBodyBytes: a.mcpBodyLimit(), PropagateRequestCancellation: true,
	})
}

type mcpFile struct {
	Path          string  `json:"path"`
	Text          *string `json:"text,omitempty"`
	ContentBase64 *string `json:"content_base64,omitempty"`
}

type mcpPublishArgs struct {
	Label          string    `json:"label,omitempty"`
	SPA            bool      `json:"spa,omitempty"`
	Password       string    `json:"password,omitempty"`
	IdempotencyKey string    `json:"idempotency_key"`
	ArchiveBase64  *string   `json:"archive_base64,omitempty"`
	Files          []mcpFile `json:"files,omitempty"`
}

func mcpDecode(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' || !utf8.Valid(raw) {
		return errors.New("invalid tool arguments")
	}
	// Unlike Decoder.Decode, Unmarshal does not allocate a second geometrically
	// growing input buffer. Validate exact/duplicate field names without copying
	// large string values first, then let encoding/json perform type validation.
	if !json.Valid(raw) {
		return errors.New("invalid tool arguments")
	}
	if err := mcpCheckFields(raw, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("invalid tool arguments")
	}
	return nil
}

// mcpCheckFields sees syntactically valid JSON only. It checks object keys
// against the destination type, rejects duplicates/case-fold aliases and skips
// string payloads in place. Every current tool schema is nonnullable, including
// optional pointer fields (pointers distinguish omission, not explicit null).
// Other JSON syntax and scalar typing stay with encoding/json.
func mcpCheckFields(data []byte, typ reflect.Type) error {
	i := 0
	bad := errors.New("invalid tool fields")
	space := func() {
		for i < len(data) && strings.ContainsRune(" \t\r\n", rune(data[i])) {
			i++
		}
	}
	skipString := func() {
		i++ // opening quote
		for i < len(data) {
			c := data[i]
			i++
			if c == '\\' {
				i++
			} else if c == '"' {
				return
			}
		}
	}
	var value func(reflect.Type, int) error
	value = func(t reflect.Type, depth int) error {
		if depth > 64 {
			return bad
		}
		space()
		if i >= len(data) {
			return bad
		}
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch data[i] {
		case 'n':
			// encoding/json silently turns null strings/bools into zero values
			// and null optional strings into nil. In particular password:null
			// must not become an omitted password and publish publicly.
			return bad
		case '{':
			if t.Kind() != reflect.Struct {
				return bad
			}
			fields := make(map[string]reflect.Type)
			for j := 0; j < t.NumField(); j++ {
				f := t.Field(j)
				fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
			}
			seen := make(map[string]bool)
			i++
			space()
			for data[i] != '}' {
				start := i
				skipString()
				if i-start > 256 {
					return bad
				}
				var key string
				if json.Unmarshal(data[start:i], &key) != nil || seen[key] || fields[key] == nil {
					return bad
				}
				seen[key] = true
				space()
				i++ // colon, guaranteed by json.Valid
				if err := value(fields[key], depth+1); err != nil {
					return err
				}
				space()
				if data[i] == ',' {
					i++
					space()
				}
			}
			i++
		case '[':
			if t.Kind() != reflect.Slice {
				return bad
			}
			i++
			space()
			count := 0
			for data[i] != ']' {
				count++
				// The only tool array is files today. Apply a hard cap to ALL
				// arrays before Unmarshal can allocate their elements, including
				// empty objects or nulls in a compact malicious request.
				if count > mcpMaxFiles {
					return errMCPArrayLimit
				}
				if err := value(t.Elem(), depth+1); err != nil {
					return err
				}
				space()
				if data[i] == ',' {
					i++
					space()
				}
			}
			i++
		case '"':
			skipString()
		default:
			for i < len(data) && !strings.ContainsRune(",}] \t\r\n", rune(data[i])) {
				i++
			}
		}
		return nil
	}
	return value(typ, 0)
}

func mcpResult(value any, failed bool) *mcp.CallToolResult {
	b, err := json.Marshal(value)
	if err != nil || len(b) > mcpOutputBytes {
		b = []byte(`{"error":"MCP output limit exceeded"}`)
		failed = true
	}
	// One JSON text copy only: duplicating inline bytes in structuredContent
	// doubles protocol output and makes client limits less predictable.
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, IsError: failed}
}

func mcpFailure(msg string) *mcp.CallToolResult {
	return mcpResult(map[string]string{"error": msg}, true)
}

func (a *apiServer) mcpCall(ctx context.Context, name string, raw json.RawMessage) *mcp.CallToolResult {
	parent, ok := ctx.Value(mcpRequestKey{}).(*http.Request)
	if !ok {
		return mcpFailure("missing authenticated request")
	}
	if name == "publish_archive" || name == "publish_files" {
		return a.mcpPublish(ctx, parent, name, raw)
	}
	var args struct {
		Token    string `json:"token,omitempty"`
		Password string `json:"password,omitempty"`
	}
	var decodeErr error
	switch name {
	case "server_info", "list_releases":
		decodeErr = mcpDecode(raw, &struct{}{})
	case "set_password":
		decodeErr = mcpDecode(raw, &args)
	default:
		var tokenOnly struct {
			Token string `json:"token"`
		}
		decodeErr = mcpDecode(raw, &tokenOnly)
		args.Token = tokenOnly.Token
	}
	if decodeErr != nil {
		return mcpFailure("invalid tool arguments")
	}
	method, target := "GET", "/_api/v1/releases"
	switch name {
	case "server_info", "list_releases":
		if args.Token != "" || args.Password != "" {
			return mcpFailure("this tool takes no arguments")
		}
		if name == "server_info" {
			target = "/_api/v1/me"
		}
	default:
		if !validToken(args.Token) || name != "set_password" && args.Password != "" {
			return mcpFailure("invalid tool arguments")
		}
		target += "/" + args.Token
	}
	var body io.Reader
	switch name {
	case "delete_release":
		method = "DELETE"
	case "set_password":
		method, target = "PUT", target+"/password"
		b, _ := json.Marshal(map[string]string{"password": args.Password})
		body = bytes.NewReader(b)
	case "reset_password":
		method, target = "POST", target+"/password/reset"
	case "remove_password":
		method, target = "DELETE", target+"/password"
	case "download_release":
		return a.mcpDownload(ctx, parent, args.Token)
	}
	w := a.mcpDispatch(ctx, parent, method, target, body, "application/json", "", mcpOutputBytes)
	return mcpAPIResult(w)
}

// A ResponseWriter with a strict retention bound, including for streaming release-core
// downloads. No httptest recorder (which would accumulate unbounded bytes).
type mcpCapture struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	limit    int
	overflow bool
}

func (w *mcpCapture) Header() http.Header { return w.header }
func (w *mcpCapture) WriteHeader(s int) {
	if w.status == 0 {
		w.status = s
	}
}
func (w *mcpCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if len(p) > w.limit-w.body.Len() {
		w.overflow = true
		return 0, errors.New("MCP output limit exceeded")
	}
	return w.body.Write(p)
}

func (a *apiServer) mcpDispatch(ctx context.Context, parent *http.Request, method, target string, body io.Reader, contentType, key string, limit int) *mcpCapture {
	r, _ := http.NewRequestWithContext(context.WithValue(ctx, internalCallKey{}, true), method, target, body)
	// Copy only the trusted request metadata needed by the API, never transport
	// session IDs or user-supplied URLs/headers.
	r.Header.Set("Authorization", "Bearer "+managementKey(parent))
	r.Header.Set("X-Fserver-Client-IP", parent.Header.Get("X-Fserver-Client-IP"))
	r.Header.Set("Content-Type", contentType)
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := &mcpCapture{header: make(http.Header), limit: limit}
	a.ServeHTTP(w, r)
	return w
}

func mcpAPIResult(w *mcpCapture) *mcp.CallToolResult {
	if w.overflow {
		return mcpFailure("MCP output limit exceeded")
	}
	if w.status == 204 {
		return mcpResult(map[string]any{"ok": true}, false)
	}
	if !json.Valid(w.body.Bytes()) {
		return mcpFailure("management operation failed")
	}
	return mcpResult(json.RawMessage(w.body.Bytes()), w.status < 200 || w.status >= 300)
}

func (a *apiServer) mcpDownload(ctx context.Context, parent *http.Request, token string) *mcp.CallToolResult {
	target := "/_api/v1/releases/" + token
	info := a.mcpDispatch(ctx, parent, "GET", target, nil, "", "", mcpOutputBytes)
	if info.status != 200 {
		return mcpAPIResult(info)
	}
	var v releaseView
	if json.Unmarshal(info.body.Bytes(), &v) != nil {
		return mcpFailure("invalid release metadata")
	}
	tooLarge := "release download exceeds the 1 MiB inline MCP limit; MCP is the only management interface, so keep your own copy of large artifacts"
	if v.Bytes > mcpInlineBytes {
		return mcpFailure(tooLarge)
	}
	w := a.mcpDispatch(ctx, parent, "GET", target+"/download", nil, "", "", mcpInlineBytes)
	if w.overflow {
		return mcpFailure(tooLarge)
	}
	if w.status != 200 {
		return mcpAPIResult(w)
	}
	return mcpResult(map[string]any{"inline": true, "content_base64": base64.StdEncoding.EncodeToString(w.body.Bytes()),
		"content_type": w.header.Get("Content-Type"), "content_disposition": w.header.Get("Content-Disposition"), "bytes": w.body.Len()}, false)
}

func (a *apiServer) mcpPublish(ctx context.Context, parent *http.Request, name string, raw json.RawMessage) *mcp.CallToolResult {
	var args mcpPublishArgs
	err := mcpDecode(raw, &args)
	if errors.Is(err, errMCPArrayLimit) {
		return mcpFailure("MCP files array exceeds the 5000-entry limit")
	}
	if err != nil || !validIdempotency(args.IdempotencyKey) || !apiValidLabel(args.Label) {
		return mcpFailure("invalid publish arguments; supply a URL-safe idempotency_key of 16..128 characters")
	}
	if len(args.Label) > 8192 || len(args.Password) > 72 {
		return mcpFailure("invalid metadata or viewer password")
	}
	var artifact io.Reader
	if name == "publish_archive" {
		if args.ArchiveBase64 == nil || args.Files != nil || len(*args.ArchiveBase64) == 0 || int64(base64.StdEncoding.DecodedLen(len(*args.ArchiveBase64))) > min(a.cfg.MaxUploadBytes, int64(mcpMaxArchiveBytes))+2 {
			return mcpFailure("invalid archive arguments or decoded archive exceeds limit")
		}
		artifact = &archiveBudgetReader{r: base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(*args.ArchiveBase64)), left: min(a.cfg.MaxUploadBytes, int64(mcpMaxArchiveBytes)), ctx: ctx}
	} else {
		if args.ArchiveBase64 != nil || len(args.Files) == 0 || len(args.Files) > min(a.cfg.MaxEntries, mcpMaxFiles) {
			return mcpFailure("invalid files arguments or entry limit exceeded")
		}
		if !a.diskOK(uint64(a.cfg.MaxUploadBytes) + uint64(a.cfg.MaxExtractBytes)*4) {
			return mcpFailure("insufficient free disk space")
		}
		f, err := os.CreateTemp(a.incoming, "api-upload-mcp-")
		if err != nil {
			return mcpFailure("could not stage files")
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if err = a.mcpWriteFiles(ctx, f, args.Files); err != nil {
			return mcpFailure("invalid files, paths, base64 or archive limits exceeded")
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return mcpFailure("could not read staged files")
		}
		artifact = f
	}
	// Only the small multipart headers live in memory. Archive base64 is decoded
	// directly into the release-core upload spool, not a second 100 MiB byte slice.
	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	p, _ := mw.CreateFormField("metadata")
	meta, _ := json.Marshal(uploadMetadata{Label: args.Label, SPA: args.SPA, Password: args.Password})
	_, _ = p.Write(meta)
	_, _ = mw.CreateFormFile("artifact", "artifact")
	header := append([]byte(nil), head.Bytes()...)
	head.Reset()
	_ = mw.Close()
	stream := io.MultiReader(bytes.NewReader(header), artifact, bytes.NewReader(head.Bytes()))
	w := a.mcpDispatch(ctx, parent, "POST", "/_api/v1/releases", stream, mw.FormDataContentType(), args.IdempotencyKey, mcpOutputBytes)
	return mcpAPIResult(w)
}

func (a *apiServer) mcpWriteFiles(ctx context.Context, f *os.File, files []mcpFile) error {
	limit := min(a.cfg.MaxUploadBytes, int64(mcpMaxArchiveBytes))
	tw := tar.NewWriter(&archiveBudgetWriter{w: f, left: limit})
	var total int64
	seen := make(map[string]bool)
	for _, file := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n := file.Path
		if n == "" || n == "." || !utf8.ValidString(n) || len(n) > 1000 || path.Clean(n) != n || strings.HasPrefix(n, "/") || strings.ContainsAny(n, "\\\x00\r\n") || seen[n] || (file.Text == nil) == (file.ContentBase64 == nil) {
			return errUnsafeArchive
		}
		for _, part := range strings.Split(n, "/") {
			if part == ".." || strings.HasPrefix(part, ".") {
				return errUnsafeArchive
			}
		}
		seen[n] = true
		name := n
		if len(files) > 1 || strings.Contains(n, "/") {
			name = "site/" + n
		}
		var source io.Reader
		var size int64
		if file.Text != nil {
			if !utf8.ValidString(*file.Text) {
				return errUnsafeArchive
			}
			size, source = int64(len(*file.Text)), strings.NewReader(*file.Text)
		} else {
			b := *file.ContentBase64
			// Standard padded base64 only. Determine exact decoded size without
			// allocating a decoded payload; the streaming decoder verifies bits.
			if len(b)%4 != 0 || strings.ContainsAny(b, "\r\n") {
				return errUnsafeArchive
			}
			size = int64(base64.StdEncoding.DecodedLen(len(b)))
			if strings.HasSuffix(b, "=") {
				size--
			}
			if strings.HasSuffix(b, "==") {
				size--
			}
			source = base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(b))
		}
		total += size
		if size < 0 || total > a.cfg.MaxExtractBytes || total > limit {
			return errArchiveLimit
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: size, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := io.Copy(tw, &archiveBudgetReader{r: source, left: size, ctx: ctx}); err != nil {
			return err
		}
	}
	return tw.Close()
}

type archiveBudgetWriter struct {
	w    io.Writer
	left int64
}

func (w *archiveBudgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, fmt.Errorf("MCP tar limit: %w", errArchiveLimit)
	}
	n, err := w.w.Write(p)
	w.left -= int64(n)
	return n, err
}
