package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const minFreeInodes uint64 = 20000

type apiConfig struct {
	Namespace       string `json:"-"`
	MaxUploadBytes  int64  `json:"max_upload_bytes"`
	MaxExtractBytes int64  `json:"max_extract_bytes"`
	MaxEntries      int    `json:"max_entries"`
	MinFreeBytes    uint64 `json:"min_free_bytes"`
	PublishLimit    int    `json:"publish_limit"`
}
type releaseView struct {
	manifest
	Protected bool   `json:"protected"`
	Username  string `json:"username,omitempty"`
}
type apiRate struct {
	count           int
	since, timeUsed time.Time
}
type apiServer struct {
	s               *store
	tokens          *tokenStore
	cfg             apiConfig
	incoming, state string
	job             chan struct{}
	mu              sync.Mutex
	rates           map[string]apiRate
	bcryptJobs      chan struct{}
	viewerCache     map[[32]byte]time.Time
	cacheSecret     [32]byte
	mcpHandler      http.Handler
	mcpAdmission    chan struct{}
}
type apiReplay struct {
	Created      time.Time   `json:"created"`
	PasswordHash string      `json:"original_password_hash,omitempty"`
	Digest       string      `json:"digest"`
	State        string      `json:"state"`
	Release      releaseView `json:"release"`
}
type uploadMetadata struct {
	Label    string `json:"label"`
	SPA      bool   `json:"spa"`
	Password string `json:"password,omitempty"`
}

func newAPIServer(s *store, tokens *tokenStore, cfg apiConfig) (*apiServer, error) {
	if s == nil || tokens == nil {
		return nil, fmt.Errorf("store and token registry are required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if !apiValidLabel(cfg.Namespace) || strings.ContainsAny(cfg.Namespace, " /\\") {
		return nil, fmt.Errorf("invalid namespace")
	}
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 100 << 20
	}
	if cfg.MaxExtractBytes == 0 {
		cfg.MaxExtractBytes = 100 << 20
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 5000
	}
	if cfg.MinFreeBytes == 0 {
		cfg.MinFreeBytes = 2 << 30
	}
	if cfg.PublishLimit == 0 {
		cfg.PublishLimit = 30
	}
	if cfg.MaxUploadBytes < 1 || cfg.MaxExtractBytes < 1 || cfg.MaxEntries < 1 || cfg.MaxEntries > 1000000 || cfg.PublishLimit < 1 || cfg.MaxUploadBytes > 1<<40 || cfg.MaxExtractBytes > 1<<40 {
		return nil, fmt.Errorf("invalid API limits")
	}
	a := &apiServer{s: s, tokens: tokens, cfg: cfg, incoming: filepath.Join(s.root, "incoming"), state: filepath.Join(s.root, "api-state"), job: make(chan struct{}, 1), rates: map[string]apiRate{}}
	a.bcryptJobs = make(chan struct{}, 4)
	a.viewerCache = make(map[[32]byte]time.Time)
	if _, err := rand.Read(a.cacheSecret[:]); err != nil {
		return nil, err
	}
	for _, p := range []string{a.incoming, a.state} {
		if err := mkdirPrivateTree(p, 0700); err != nil {
			return nil, err
		}
	}
	if err := a.cleanup(time.Now()); err != nil {
		return nil, err
	}
	a.mcpAdmission = make(chan struct{}, 1)
	a.mcpHandler = a.newMCPHandler()
	return a, nil
}
func (a *apiServer) cleanup(now time.Time) error {
	for _, dir := range []string{a.incoming, a.state} {
		es, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range es {
			name := e.Name()
			owned := strings.HasPrefix(name, "api-upload-") || strings.HasPrefix(name, "api-extract-")
			if dir == a.state {
				owned = strings.HasPrefix(name, ".api-replay-")
			}
			if owned {
				st, err := e.Info()
				if err != nil {
					return err
				}
				if now.Sub(st.ModTime()) > 24*time.Hour {
					p := filepath.Join(dir, name)
					if e.IsDir() {
						removeStage(p)
					} else if err = os.Remove(p); err != nil {
						return err
					}
				}
				continue
			}
			if dir == a.state && isReplayFilename(name) {
				p := filepath.Join(dir, name)
				r, err := readReplay(p)
				if err == nil && now.Sub(r.Created) > 24*time.Hour {
					if err = os.Remove(p); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func isReplayFilename(n string) bool {
	if len(n) != 69 || !strings.HasSuffix(n, ".json") {
		return false
	}
	_, e := hex.DecodeString(n[:64])
	return e == nil
}
func readReplay(p string) (apiReplay, error) {
	var r apiReplay
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return r, e
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return r, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 32768 {
		return r, errors.New("invalid private replay record")
	}
	d := json.NewDecoder(io.LimitReader(f, 32769))
	d.DisallowUnknownFields()
	e = d.Decode(&r)
	if e == nil {
		var extra any
		if next := d.Decode(&extra); next != io.EOF {
			e = errors.New("trailing replay state")
		}
	}
	if e == nil && (r.Created.IsZero() || r.Digest == "" || (r.State != "pending" && r.State != "complete")) {
		e = errors.New("invalid replay state")
	}
	return r, e
}
func (a *apiServer) writeReplay(p string, r apiReplay) error {
	f, e := os.CreateTemp(a.state, ".api-replay-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	e = json.NewEncoder(f).Encode(r)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), p); e != nil {
		return e
	}
	d, e := os.Open(a.state)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (a *apiServer) rate(key string, limit int, window time.Duration, increment bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	r, ok := a.rates[key]
	if ok && now.Sub(r.since) >= window {
		delete(a.rates, key)
		r = apiRate{}
		ok = false
	}
	if !ok && len(a.rates) >= 4096 {
		oldest := ""
		var when time.Time
		for k, v := range a.rates {
			if now.Sub(v.timeUsed) > time.Hour {
				delete(a.rates, k)
				continue
			}
			if oldest == "" || v.timeUsed.Before(when) {
				oldest = k
				when = v.timeUsed
			}
		}
		if len(a.rates) >= 4096 {
			delete(a.rates, oldest)
		}
	}
	if r.count >= limit {
		return false
	}
	if increment {
		if !ok {
			r.since = now
		}
		r.count++
		r.timeUsed = now
		a.rates[key] = r
	}
	return true
}
func clientIP(r *http.Request) string {
	ip, e := netip.ParseAddr(r.Header.Get("X-Fserver-Client-IP"))
	if e != nil {
		return "unknown"
	}
	return ip.Unmap().String()
}

type apiResponse struct {
	http.ResponseWriter
	status    int
	release   string
	ambiguous bool
}

func (w *apiResponse) WriteHeader(s int) {
	if w.status == 0 {
		w.status = s
		w.ResponseWriter.WriteHeader(s)
	}
}
func (w *apiResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func apiError(w http.ResponseWriter, status int, id, msg string) {
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	apiJSON(w, status, map[string]string{"error": msg, "request_id": id})
}
func requestID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

// managementKey returns the agent key from "Authorization: Bearer KEY" or,
// only when no Authorization header is present, from "X-Auth-Token: KEY".
// Some MCP hosts reserve Authorization for OAuth and send static keys in a
// custom header. Never both: an Authorization header is always authoritative.
func managementKey(r *http.Request) string {
	if raw := r.Header.Get("Authorization"); raw != "" {
		if strings.HasPrefix(raw, "Bearer ") && len(raw) <= 512 && !strings.ContainsAny(raw[7:], " \t\r\n") {
			return raw[7:]
		}
		return ""
	}
	raw := r.Header.Get("X-Auth-Token")
	if raw != "" && len(raw) <= 505 && !strings.ContainsAny(raw, " \t\r\n") {
		return raw
	}
	return ""
}

// mcpListMax bounds list_releases output (newest first).
const mcpListMax = 1000

// internalCallKey marks requests dispatched in-process by the MCP adapter.
type internalCallKey struct{}

func (a *apiServer) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	w := &apiResponse{ResponseWriter: out}
	start := time.Now()
	id := requestID()
	operation := "unknown"
	agent := ""
	token := ""
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", id)
	defer func() {
		if token == "" {
			token = w.release
		}
		b, _ := json.Marshal(map[string]any{"ambiguous": w.ambiguous, "operation": operation, "status": w.status, "duration_ms": time.Since(start).Milliseconds(), "agent": agent, "release": token, "request_id": id})
		_ = json.NewEncoder(os.Stderr).Encode(json.RawMessage(b))
	}()
	// Service is Unix-only. These endpoints must never be routed by public Caddy.
	if r.URL.Path == "/_internal/health" && canonicalAPIPath(r) {
		operation = "health"
		if r.Method != "GET" {
			methodError(w, id, "GET")
			return
		}
		apiJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/_internal/authorize" && canonicalAPIPath(r) {
		operation = "authorize"
		a.authorize(w, r, id)
		return
	}
	// MCP is the only public management interface. The release core under
	// /_api/v1 answers only in-process calls from the MCP adapter.
	if r.URL.Path != "/mcp" && r.Context().Value(internalCallKey{}) == nil {
		apiError(w, 404, id, "not found")
		return
	}
	// Authenticate before inspecting paths or reading any request body.
	key := "auth:" + clientIP(r)
	raw := managementKey(r)
	var identity agentIdentity
	var err error
	if raw != "" {
		identity, err = a.tokens.Authenticate(raw, time.Now())
	} else {
		err = errors.New("invalid authentication")
	}
	if err != nil {
		if !a.rate(key, 10, time.Minute, true) {
			apiError(w, 429, id, "too many authentication failures")
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		apiError(w, 401, id, "authentication required")
		return
	}
	agent = identity.Label
	if !canonicalAPIPath(r) {
		apiError(w, 404, id, "not found")
		return
	}
	if r.URL.Path == "/mcp" {
		operation = "mcp"
		a.serveMCP(w, r, id)
		return
	}
	if r.URL.Path == "/_api/v1/me" {
		operation = "me"
		if r.Method != "GET" {
			methodError(w, id, "GET")
			return
		}
		apiJSON(w, 200, map[string]any{"namespace": a.cfg.Namespace, "agent": identity.Label, "limits": map[string]any{"max_upload_bytes": a.cfg.MaxUploadBytes, "max_extract_bytes": a.cfg.MaxExtractBytes, "max_entries": a.cfg.MaxEntries, "min_free_bytes": a.cfg.MinFreeBytes, "min_free_inodes": minFreeInodes, "publish_limit": a.cfg.PublishLimit, "publish_window_seconds": 3600, "request_timeout_seconds": 170}})
		return
	}
	if r.URL.Path == "/_api/v1/releases" {
		switch r.Method {
		case "GET":
			operation = "list"
			ms, e := a.s.list()
			if e != nil {
				apiError(w, 500, id, "could not list releases")
				return
			}
			// Bound JSON serialization and MCP capture size: the list is sorted
			// newest first, so return only the newest releases.
			if len(ms) > mcpListMax {
				ms = ms[:mcpListMax]
			}
			views := make([]releaseView, 0, len(ms))
			for _, m := range ms {
				v, e := a.view(m)
				if e != nil {
					apiError(w, 500, id, "could not read release policy")
					return
				}
				views = append(views, v)
			}
			apiJSON(w, 200, views)
		case "POST":
			operation = "publish"
			a.upload(w, r, id, identity)
		default:
			methodError(w, id, "GET, POST")
		}
		return
	}
	prefix := "/_api/v1/releases/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		apiError(w, 404, id, "not found")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) == 0 || !validToken(parts[0]) {
		apiError(w, 404, id, "not found")
		return
	}
	token = parts[0]
	suffix := strings.Join(parts[1:], "/")
	allow := ""
	switch suffix {
	case "":
		allow = "GET, DELETE"
	case "download":
		allow = "GET"
	case "password":
		allow = "PUT, DELETE"
	case "password/reset":
		allow = "POST"
	default:
		apiError(w, 404, id, "not found")
		return
	}
	found := false
	for _, m := range strings.Split(allow, ", ") {
		if r.Method == m {
			found = true
		}
	}
	if !found {
		methodError(w, id, allow)
		return
	}
	m, e := a.s.info(token)
	if e != nil {
		apiError(w, 404, id, "release not found")
		return
	}
	switch suffix {
	case "":
		if r.Method == "GET" {
			operation = "info"
			v, e := a.view(m)
			if e != nil {
				apiError(w, 500, id, "could not read release policy")
				return
			}
			apiJSON(w, 200, v)
		} else {
			operation = "delete"
			if _, e = a.s.deleteRelease(token); e != nil {
				apiError(w, 500, id, "could not delete release")
				return
			}
			w.WriteHeader(204)
		}
	case "download":
		operation = "download"
		a.download(w, r, id, m)
	case "password", "password/reset":
		operation = "password"
		a.password(w, r, id, m, suffix == "password/reset")
	}
}
func canonicalAPIPath(r *http.Request) bool {
	return r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" && r.URL.EscapedPath() == r.URL.Path && path.Clean(r.URL.Path) == r.URL.Path && !strings.Contains(r.URL.Path, "\\")
}
func methodError(w http.ResponseWriter, id, allow string) {
	w.Header().Set("Allow", allow)
	apiError(w, 405, id, "method not allowed")
}
func (a *apiServer) view(m manifest) (releaseView, error) {
	p, e := a.s.policy(m.Token)
	v := releaseView{manifest: m, Protected: p.Protected}
	if p.Protected {
		v.Username = "viewer"
	}
	return v, e
}
func decodeJSON(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, 16385))
	if err != nil {
		return err
	}
	if len(data) > 16384 {
		return errors.New("JSON exceeds limit")
	}
	return strictJSON(data, v)
}
func apiValidLabel(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > 200 {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (a *apiServer) password(w http.ResponseWriter, r *http.Request, id string, m manifest, reset bool) {
	password := ""
	if reset {
		var b [24]byte
		if _, e := rand.Read(b[:]); e != nil {
			apiError(w, 500, id, "could not generate password")
			return
		}
		password = base64.RawURLEncoding.EncodeToString(b[:])
	} else if r.Method == "PUT" {
		var body struct {
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if e := decodeJSON(r.Body, &body); e != nil {
			apiError(w, 400, id, "invalid password request")
			return
		}
		if body.Password == "" {
			apiError(w, 400, id, "password removal requires DELETE")
			return
		}
		password = body.Password
	}
	p, e := makeAccessPolicy(password)
	if e != nil {
		apiError(w, 400, id, "password must be 8 to 72 UTF-8 bytes without control characters")
		return
	}
	if e = a.s.setPolicy(m.Token, p); e != nil {
		apiError(w, 500, id, "could not update release policy")
		return
	}
	v := releaseView{manifest: m, Protected: p.Protected}
	if p.Protected {
		v.Username = "viewer"
	}
	if reset {
		apiJSON(w, 200, map[string]any{"release": v, "username": "viewer", "password": password})
	} else {
		apiJSON(w, 200, v)
	}
}
func validIdempotency(s string) bool {
	if len(s) < 16 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func (a *apiServer) diskOK(needed uint64) bool {
	var st syscall.Statfs_t
	if syscall.Statfs(a.incoming, &st) != nil {
		return false
	}
	return apiDiskAvailable(st, a.cfg, needed)
}

// Preserve inode headroom as well as bytes: an archive of empty files must not
// exhaust the filesystem and prevent policy or credential-revocation writes.
// Filesystems with no fixed inode budget report Files==0 and skip this check.
func apiDiskAvailable(st syscall.Statfs_t, cfg apiConfig, needed uint64) bool {
	if st.Bsize <= 0 || cfg.MaxEntries < 1 {
		return false
	}
	blockSize := uint64(st.Bsize)
	free := ^uint64(0)
	if st.Bavail <= free/blockSize {
		free = st.Bavail * blockSize
	}
	if free < cfg.MinFreeBytes || free-cfg.MinFreeBytes < needed {
		return false
	}
	if st.Files > 0 {
		// Config validation caps MaxEntries at one million, so this cannot overflow.
		required := minFreeInodes + 5*uint64(cfg.MaxEntries) + 32
		if st.Ffree < required {
			return false
		}
	}
	return true
}
func (a *apiServer) upload(w http.ResponseWriter, r *http.Request, id string, identity agentIdentity) {
	key := r.Header.Get("Idempotency-Key")
	if !validIdempotency(key) {
		apiError(w, 400, id, "a URL-safe Idempotency-Key of 16 to 128 characters is required")
		return
	}
	if !a.rate("publish:"+identity.ID, a.cfg.PublishLimit, time.Hour, true) {
		apiError(w, 429, id, "publish attempt limit reached")
		return
	}
	select {
	case a.job <- struct{}{}:
		defer func() { <-a.job }()
	default:
		apiError(w, 429, id, "publisher busy; retry with the same key and bytes")
		return
	}
	if err := a.cleanup(time.Now()); err != nil {
		apiError(w, 500, id, "could not maintain private API state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 170*time.Second)
	defer cancel()
	// Reserve for the spool, extracted source, publisher copy, and sidecars.
	needed := uint64(a.cfg.MaxUploadBytes) + uint64(a.cfg.MaxExtractBytes)*4
	if !a.diskOK(needed) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxUploadBytes+65536)
	_, params, contentErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentErr != nil || params["boundary"] == "" {
		apiError(w, 400, id, "expected multipart metadata then artifact")
		return
	}
	guard := &multipartEndGuard{ReadCloser: r.Body, marker: []byte("\r\n--" + params["boundary"] + "--")}
	r.Body = guard
	mr, e := r.MultipartReader()
	if e != nil {
		apiError(w, 400, id, "expected multipart metadata then artifact")
		return
	}
	p, e := mr.NextRawPart()
	if e != nil || (p.FormName() != "metadata" || p.Header.Get("Content-Transfer-Encoding") != "") {
		apiError(w, 400, id, "metadata must be the first part")
		return
	}
	metadataBytes, e := io.ReadAll(io.LimitReader(p, 16385))
	if e != nil || len(metadataBytes) > 16384 {
		apiError(w, 400, id, "invalid metadata")
		return
	}
	var meta uploadMetadata
	if e = decodeJSON(strings.NewReader(string(metadataBytes)), &meta); e != nil || !apiValidLabel(meta.Label) {
		apiError(w, 400, id, "invalid metadata or label")
		return
	}
	policy, e := makeAccessPolicy(meta.Password)
	if e != nil {
		apiError(w, 400, id, "invalid viewer password")
		return
	}
	p, e = mr.NextRawPart()
	if e != nil || (p.FormName() != "artifact" || p.Header.Get("Content-Transfer-Encoding") != "") {
		apiError(w, 400, id, "artifact must be the second part")
		return
	}
	f, e := os.CreateTemp(a.incoming, "api-upload-")
	if e != nil {
		apiError(w, 500, id, "could not stage upload")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	digestMetadata := meta
	digestMetadata.Password = ""
	canonical, _ := json.Marshal(digestMetadata)
	h := sha256.New()
	h.Write(canonical)
	h.Write([]byte{0})
	reader := &archiveBudgetReader{r: p, left: a.cfg.MaxUploadBytes, ctx: ctx}
	_, e = io.Copy(io.MultiWriter(f, h), reader)
	if e != nil {
		a.bodyError(w, id, e)
		return
	}
	if _, e = mr.NextRawPart(); e != io.EOF {
		if e == nil {
			e = errUnsafeArchive
		}
		a.bodyError(w, id, e)
		return
	}
	// MultipartReader stops at its closing boundary. Any bytes after it are not
	// part of the agreed request, including otherwise ignored MIME epilogues.
	// The total-body cap remains in force while exhausting the HTTP body.
	extra, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil {
		a.bodyError(w, id, e)
		return
	}
	if len(extra) > 0 || !guard.valid() {
		apiError(w, 400, id, "unexpected data after multipart body")
		return
	}
	digest := hex.EncodeToString(h.Sum(nil))
	kh := sha256.Sum256([]byte(identity.ID + "\x00" + key))
	rp := filepath.Join(a.state, hex.EncodeToString(kh[:])+".json")
	old, e := readReplay(rp)
	if e == nil && time.Since(old.Created) <= 24*time.Hour {
		if rw, ok := w.(*apiResponse); ok && validToken(old.Release.Token) {
			rw.release = old.Release.Token
		}
		passwordMatches := meta.Password == "" && old.PasswordHash == ""
		if old.PasswordHash != "" {
			passwordMatches = (accessPolicy{Protected: true, PasswordHash: old.PasswordHash, UpdatedAt: old.Created}).Check("viewer", meta.Password)
		}
		if old.Digest != digest || !passwordMatches {
			apiError(w, 409, id, "idempotency key was used with a different body")
			return
		}
		if old.State != "complete" {
			if rw, ok := w.(*apiResponse); ok {
				rw.ambiguous = true
			}
			apiError(w, 409, id, "previous publish outcome is ambiguous; list your uploads before retrying")
			return
		}
		current, currentErr := a.s.info(old.Release.Token)
		if currentErr != nil {
			apiError(w, 409, id, "original release is no longer active")
			return
		}
		view, viewErr := a.view(current)
		if viewErr != nil {
			apiError(w, 500, id, "could not read release policy")
			return
		}
		apiJSON(w, 201, view)
		return
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		if rw, ok := w.(*apiResponse); ok {
			rw.ambiguous = true
		}
		apiError(w, 409, id, "previous publish outcome is ambiguous; list your uploads")
		return
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		apiError(w, 500, id, "could not read staged upload")
		return
	}
	dir, e := os.MkdirTemp(a.incoming, "api-extract-")
	if e != nil {
		apiError(w, 500, id, "could not stage archive")
		return
	}
	defer removeStage(dir)
	source, e := extractArtifact(ctx, f, dir, a.cfg)
	if e != nil {
		a.bodyError(w, id, e)
		return
	}
	// Validate before persisting intent so a normal publisher validation refusal
	// is a correctable 422, not a permanently ambiguous idempotency key.
	plan, e := inspectSource(source)
	if e != nil {
		apiError(w, 422, id, "publisher refused artifact: prepare clean static output without hidden files, secrets, source code, links or supplied sidecars")
		return
	}
	single, hasIndex := plan.single, plan.hasIndex
	plan.root.Close()
	if meta.SPA && (single || !hasIndex) {
		apiError(w, 422, id, "SPA requires a directory with a root index.html")
		return
	}
	if ctx.Err() != nil {
		apiError(w, 408, id, "request cancelled or timed out")
		return
	}
	if !a.diskOK(uint64(a.cfg.MaxExtractBytes) * 3) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	record := apiReplay{Created: time.Now().UTC(), Digest: digest, State: "pending", PasswordHash: policy.PasswordHash}
	if e = a.writeReplay(rp, record); e != nil {
		apiError(w, 500, id, "could not persist publish intent")
		return
	}
	m, _, e := a.s.publishWithPolicyContext(ctx, source, meta.Label, meta.SPA, policy)
	if rw, ok := w.(*apiResponse); ok && validToken(m.Token) {
		rw.release = m.Token
	}
	if e != nil { // Intent is deliberately retained: activation may have happened.
		if rw, ok := w.(*apiResponse); ok {
			rw.ambiguous = true
		}
		apiError(w, 500, id, "publish failed; list your uploads before retrying with a new key")
		return
	}
	record.State = "complete"
	record.Release = releaseView{manifest: m, Protected: policy.Protected}
	if policy.Protected {
		record.Release.Username = "viewer"
	}
	if e = a.writeReplay(rp, record); e != nil {
		if rw, ok := w.(*apiResponse); ok {
			rw.ambiguous = true
		}
		apiError(w, 500, id, "publish outcome is ambiguous; list your uploads before retrying")
		return
	}
	apiJSON(w, 201, record.Release)
}
func (a *apiServer) bodyError(w http.ResponseWriter, id string, e error) {
	var max *http.MaxBytesError
	switch {
	case errors.As(e, &max) || errors.Is(e, errArchiveLimit):
		apiError(w, 413, id, "upload or archive limit exceeded")
	case errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded):
		apiError(w, 408, id, "request cancelled or timed out")
	default:
		apiError(w, 400, id, "malformed or unsafe upload archive")
	}
}
func (a *apiServer) download(w http.ResponseWriter, r *http.Request, id string, m manifest) {
	root := filepath.Join(a.s.public, m.Token)
	if m.OriginalFilename != "" {
		if filepath.Base(m.OriginalFilename) != m.OriginalFilename || strings.HasPrefix(m.OriginalFilename, ".") {
			apiError(w, 500, id, "invalid stored release")
			return
		}
		f, e := os.OpenFile(filepath.Join(root, m.OriginalFilename), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			apiError(w, 404, id, "release file not found")
			return
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() {
			apiError(w, 500, id, "invalid stored release")
			return
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": m.OriginalFilename}))
		http.ServeContent(w, r, m.OriginalFilename, st.ModTime(), f)
		return
	}
	if m.SourceBasename == "" || filepath.Base(m.SourceBasename) != m.SourceBasename || strings.HasPrefix(m.SourceBasename, ".") {
		apiError(w, 500, id, "invalid stored release")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": m.SourceBasename + ".tar.gz"}))
	if e := writeOriginalArchive(r.Context(), w, root, m.SourceBasename); e != nil { // Status may already be sent; never emit paths or compressor diagnostics.
		if rw, ok := w.(*apiResponse); ok && rw.status == 0 {
			apiError(w, 500, id, "could not download release")
		}
	}
}

// Authorize the same canonical URI that the static server will receive. Reject
// rather than clean ambiguous paths: cleaning A/../B after authorizing A could
// otherwise turn a public release into a password bypass for B. url.ParseRequestURI
// unescapes exactly once, matching Go's request URL and Caddy's file server.
// A literal percent (including a literal "%2e") in that decoded path is a real
// filename, not a request to decode twice.
func authorizedURIToken(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 16384 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\x00") {
		return "", false
	}
	u, e := url.ParseRequestURI(raw)
	if e != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return "", false
	}
	p := u.Path
	if strings.ContainsAny(p, "\\\x00\r\n") || strings.Contains(p, "//") {
		return "", false
	}
	trimmed := strings.TrimSuffix(p, "/")
	if path.Clean(trimmed) != trimmed {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(trimmed, "/"), "/")
	if len(parts) == 0 || !validToken(parts[0]) {
		return "", false
	}
	for _, s := range parts {
		if s == "." || s == ".." || s == "" || strings.HasPrefix(s, ".") {
			return "", false
		}
	}
	return parts[0], true
}
func (a *apiServer) authorize(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != "GET" && r.Method != "HEAD" {
		methodError(w, id, "GET, HEAD")
		return
	}
	token, ok := authorizedURIToken(r.Header.Get("X-Forwarded-Uri"))
	if !ok {
		apiError(w, 404, id, "not found")
		return
	}
	if _, e := a.s.info(token); e != nil {
		apiError(w, 404, id, "not found")
		return
	}
	p, e := a.s.policy(token)
	if e != nil {
		apiError(w, 404, id, "not found")
		return
	}
	if p.Protected {

		key := "viewer-guess:" + clientIP(r) + ":" + token
		username, password, basicOK := "", "", false
		if len(r.Header.Get("Authorization")) <= 1024 {
			username, password, basicOK = r.BasicAuth()
		}
		shaped := basicOK && username == "viewer" && len(password) >= 8 && len(password) <= 72 && utf8.ValidString(password)
		if shaped {
			for _, c := range password {
				if unicode.IsControl(c) {
					shaped = false
					break
				}
			}
		}
		valid := false
		if shaped {
			cacheKey := a.viewerCacheKey(token, p.PasswordHash, username, password)
			valid = a.cachedViewer(cacheKey)
			if !valid {
				// Cache hits bypass this budget. New login attempts are bounded before
				// bcrypt; a shared-IP attacker may temporarily delay NEW logins for this
				// release, but cannot knock out cached authenticated asset requests.
				if !a.rate(key, 10, time.Minute, true) {
					apiError(w, 429, id, "new viewer login attempts temporarily limited")
					return
				}
				select {
				case a.bcryptJobs <- struct{}{}:
					valid = p.Check(username, password)
					<-a.bcryptJobs
				default:
					apiError(w, 429, id, "viewer authentication busy; retry shortly")
					return
				}
				if valid {
					a.rememberViewer(cacheKey)
				}
			}
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Basic realm="fserver-`+token+`", charset="UTF-8"`)
			apiError(w, 401, id, "viewer authentication required")
			return
		}

		w.Header().Set("X-Fserver-Cache-Control", "private, no-store")
	} else {
		w.Header().Set("X-Fserver-Cache-Control", "public, max-age=3600")
	}
	w.WriteHeader(204)
}

// multipart.Reader privately buffers past the terminal boundary. Track the raw
// stream as well, so MIME epilogues cannot be silently accepted from that buffer.
type multipartEndGuard struct {
	io.ReadCloser
	marker, tail, suffix []byte
	found, bad           bool
}

func (g *multipartEndGuard) Read(p []byte) (int, error) {
	n, e := g.ReadCloser.Read(p)
	if n > 0 {
		if g.found {
			if len(g.suffix)+n > 2 {
				g.bad = true
			}
			if len(g.suffix) < 3 {
				keep := n
				if keep > 3-len(g.suffix) {
					keep = 3 - len(g.suffix)
				}
				g.suffix = append(g.suffix, p[:keep]...)
			}
		} else {
			data := append(g.tail, p[:n]...)
			if i := bytes.Index(data, g.marker); i >= 0 {
				g.found = true
				g.suffix = append([]byte(nil), data[i+len(g.marker):]...)
				if len(g.suffix) > 2 {
					g.bad = true
					g.suffix = g.suffix[:3]
				}
				g.tail = nil
			} else {
				keep := len(g.marker) - 1
				if keep > len(data) {
					keep = len(data)
				}
				g.tail = append([]byte(nil), data[len(data)-keep:]...)
			}
		}
	}
	return n, e
}
func (g *multipartEndGuard) valid() bool {
	return g.found && !g.bad && (len(g.suffix) == 0 || bytes.Equal(g.suffix, []byte("\r\n")))
}

// A cache hit is bound to the release's CURRENT bcrypt hash, so policy changes
// invalidate it immediately. Credentials and the per-process HMAC key never
// leave memory. Cached authenticated visitors bypass the per-IP/per-release
// guess budget. Uncached new logins may be briefly throttled behind a shared NAT.
func (a *apiServer) viewerCacheKey(token, hash, username, password string) [32]byte {
	h := hmac.New(sha256.New, a.cacheSecret[:])
	for _, s := range []string{token, hash, username, password} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}
func (a *apiServer) cachedViewer(key [32]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	expiry, ok := a.viewerCache[key]
	if !ok {
		return false
	}
	if time.Now().Before(expiry) {
		return true
	}
	delete(a.viewerCache, key)
	return false
}
func (a *apiServer) rememberViewer(key [32]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.viewerCache) >= 512 {
		var oldestKey [32]byte
		var oldest time.Time
		for k, expiry := range a.viewerCache {
			if !expiry.After(now) {
				delete(a.viewerCache, k)
				continue
			}
			if oldest.IsZero() || expiry.Before(oldest) {
				oldest = expiry
				oldestKey = k
			}
		}
		if len(a.viewerCache) >= 512 {
			delete(a.viewerCache, oldestKey)
		}
	}
	a.viewerCache[key] = now.Add(10 * time.Minute)
}
