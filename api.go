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
	"hash"
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
	// DefaultExpiryDays applies to new releases published without
	// expires_in_days; 0 means they never expire. The serve command defaults
	// it to 60 (FSERVER_DEFAULT_EXPIRY_DAYS).
	DefaultExpiryDays int `json:"default_expiry_days"`
}

// maxExpiryDays bounds expires_in_days and FSERVER_DEFAULT_EXPIRY_DAYS (about ten years).
const maxExpiryDays = 3650

type releaseView struct {
	manifest
	Protected bool   `json:"protected"`
	Username  string `json:"username,omitempty"`
	// Notice is set on publish, update and set_expiry results: one sentence
	// on when the release is deleted and how to change that.
	Notice string `json:"notice,omitempty"`
}
type apiRate struct {
	count           int
	since, timeUsed time.Time
}
type apiServer struct {
	s                 *store
	tokens            *tokenStore
	cfg               apiConfig
	incoming, state   string
	job               chan struct{}
	mu                sync.Mutex
	rates             map[string]apiRate
	bcryptJobs        chan struct{}
	viewerCache       map[[32]byte]time.Time
	cacheSecret       [32]byte
	mcpHandler        http.Handler
	mcpAdmission      chan struct{}
	mcpSmallAdmission chan struct{}
	tickets           map[[32]byte]uploadTicket
	uploadSlot        chan struct{}
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
	// Token replaces the content of that existing release in place.
	Token string `json:"token,omitempty"`
	// ExpiresInDays: nil is the server default for a new release and keeps
	// the current expiry on an update; 0 never expires.
	ExpiresInDays *int `json:"expires_in_days,omitempty"`
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
	// Defaults for ticket uploads; MCP inline publishing is capped lower (mcpLimits).
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 1 << 30
	}
	if cfg.MaxExtractBytes == 0 {
		cfg.MaxExtractBytes = 1 << 30
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 50000
	}
	if cfg.MinFreeBytes == 0 {
		cfg.MinFreeBytes = 2 << 30
	}
	if cfg.PublishLimit == 0 {
		cfg.PublishLimit = 30
	}
	if cfg.MaxUploadBytes < 1 || cfg.MaxExtractBytes < 1 || cfg.MaxEntries < 1 || cfg.MaxEntries > 1000000 || cfg.PublishLimit < 1 || cfg.MaxUploadBytes > 1<<40 || cfg.MaxExtractBytes > 1<<40 || cfg.DefaultExpiryDays < 0 || cfg.DefaultExpiryDays > maxExpiryDays {
		return nil, fmt.Errorf("invalid API limits")
	}
	a := &apiServer{s: s, tokens: tokens, cfg: cfg, incoming: filepath.Join(s.root, "incoming"), state: filepath.Join(s.root, "api-state"), job: make(chan struct{}, 1), rates: map[string]apiRate{}}
	a.bcryptJobs = make(chan struct{}, 4)
	a.tickets = make(map[[32]byte]uploadTicket)
	a.uploadSlot = make(chan struct{}, 1)
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
	a.mcpSmallAdmission = make(chan struct{}, mcpSmallSlots)
	handler, err := a.newMCPHandler()
	if err != nil {
		return nil, err
	}
	a.mcpHandler = handler
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
		// Every service response is no-store, whatever a handler set: the MCP SDK
		// writes "no-cache, no-transform" on event streams, which permits storing.
		cc := "no-store"
		if strings.Contains(w.Header().Get("Cache-Control"), "no-transform") {
			cc = "no-store, no-transform"
		}
		w.Header().Set("Cache-Control", cc)
		w.ResponseWriter.WriteHeader(s)
	}
}

// Unwrap lets http.ResponseController reach the connection (upload deadlines).
func (w *apiResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
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
	// forward_auth keeps the visitor's query on this rewritten URI: Caddy's
	// rewrite replaces a query only when `uri` sets one, and never clears a bare
	// "?". The visitor URI is read only from X-Forwarded-Uri, so ignore it here.
	if r.URL.Path == "/_internal/authorize" && canonicalPath(r) {
		operation = "authorize"
		a.authorize(w, r, id)
		return
	}
	// One-time upload tickets: their own credential, never a management key.
	if r.URL.Path == "/_upload" && r.Context().Value(internalCallKey{}) == nil {
		operation = "upload"
		a.serveUpload(w, r, id, &agent)
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
		a.serveMCP(w, r, id, identity)
		return
	}
	if r.URL.Path == "/_api/v1/me" {
		operation = "me"
		if r.Method != "GET" {
			methodError(w, id, "GET")
			return
		}
		// "limits" applies to publish_archive/publish_files; "upload" to begin_upload.
		mcpLimits := a.mcpLimits()
		// disk is null if the filesystem cannot be read; the rest still helps.
		var disk *diskReport
		var st syscall.Statfs_t
		if syscall.Statfs(a.incoming, &st) == nil {
			r := diskReportFor(st, a.cfg, mcpLimits)
			disk = &r
		}
		apiJSON(w, 200, map[string]any{"version": buildVersion, "namespace": a.cfg.Namespace, "agent": identity.Label, "account": identity.Account,
			"default_expiry_days": a.cfg.DefaultExpiryDays, "disk": disk,
			"limits": map[string]any{"max_upload_bytes": mcpLimits.MaxUploadBytes, "max_extract_bytes": mcpLimits.MaxExtractBytes, "max_entries": mcpLimits.MaxEntries, "min_free_bytes": a.cfg.MinFreeBytes, "min_free_inodes": minFreeInodes, "publish_limit": a.cfg.PublishLimit, "publish_window_seconds": 3600, "request_timeout_seconds": 170},
			"upload": map[string]any{"max_bytes": a.cfg.MaxUploadBytes, "max_extract_bytes": a.cfg.MaxExtractBytes, "max_entries": a.cfg.MaxEntries, "ticket_seconds": int(uploadTicketTTL / time.Second), "max_pending_tickets": uploadMaxPending}})
		return
	}
	if r.URL.Path == "/_api/v1/uploads" {
		operation = "begin_upload"
		if r.Method != "POST" {
			methodError(w, id, "POST")
			return
		}
		a.beginUpload(w, r, id, identity)
		return
	}
	if r.URL.Path == "/_api/v1/releases" {
		switch r.Method {
		case "GET":
			operation = "list"
			all, e := a.s.list()
			if e != nil {
				apiError(w, 500, id, "could not list releases")
				return
			}
			// A key lists, counts and totals only its own account's releases.
			ms := make([]manifest, 0, len(all))
			for _, m := range all {
				if m.account() == identity.Account {
					ms = append(ms, m)
				}
			}
			// Totals cover every active release of the account; the views are bounded for JSON
			// serialization and MCP capture size: newest first, so the newest.
			var total int64
			expiring := 0
			soon := time.Now().Add(7 * 24 * time.Hour)
			for _, m := range ms {
				total += m.Bytes
				if m.ExpiresAt != nil && m.ExpiresAt.Before(soon) {
					expiring++
				}
			}
			count := len(ms)
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
			apiJSON(w, 200, map[string]any{"releases": views, "count": count, "total_bytes": total,
				"truncated": count > len(views), "expiring_within_7_days": expiring})
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
	case "expiry":
		allow = "PUT"
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
	// Another account's release is answered exactly like an unknown token, so a
	// key cannot learn that it exists.
	if e != nil || m.account() != identity.Account {
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
	case "expiry":
		operation = "expiry"
		a.expiry(w, r, id, m)
	}
}

// expiresAt turns expires_in_days into an expiry. nil days means the server
// default for a new release and "keep the current expiry" for an update.
func (a *apiServer) expiresAt(days *int, update bool, now time.Time) (at *time.Time, keep, ok bool) {
	n := a.cfg.DefaultExpiryDays
	if days != nil {
		n = *days
	} else if update {
		return nil, true, true
	}
	if n < 0 || n > maxExpiryDays {
		return nil, false, false
	}
	if n == 0 {
		return nil, false, true
	}
	t := now.UTC().Add(time.Duration(n) * 24 * time.Hour).Truncate(time.Second)
	return &t, false, true
}

// expiryNotice tells the agent, in the result it reads anyway, when the
// release will be deleted and how to keep it.
func expiryNotice(m manifest, now time.Time) string {
	if m.ExpiresAt == nil {
		return "This release does not expire: it stays online until delete_release. Call set_expiry with expires_in_days to have it deleted automatically."
	}
	days := int((m.ExpiresAt.Sub(now) + 24*time.Hour - time.Second) / (24 * time.Hour))
	return fmt.Sprintf("This release will be deleted automatically at %s (in %d days). "+
		"If it must stay online longer, call set_expiry with a larger expires_in_days, or 0 to keep it forever; "+
		"tell the user when the link stops working.", m.ExpiresAt.UTC().Format(time.RFC3339), max(days, 0))
}

func (a *apiServer) expiry(w http.ResponseWriter, r *http.Request, id string, m manifest) {
	var body struct {
		ExpiresInDays *int `json:"expires_in_days"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if e := decodeJSON(r.Body, &body); e != nil || body.ExpiresInDays == nil {
		apiError(w, 400, id, "expires_in_days must be an integer from 0 to 3650")
		return
	}
	at, _, ok := a.expiresAt(body.ExpiresInDays, false, time.Now())
	if !ok {
		apiError(w, 400, id, "expires_in_days must be an integer from 0 to 3650")
		return
	}
	m, e := a.s.setExpiry(m.Token, at)
	if e != nil {
		apiError(w, 500, id, "could not update release expiry")
		return
	}
	v, e := a.view(m)
	if e != nil {
		apiError(w, 500, id, "could not read release policy")
		return
	}
	v.Notice = expiryNotice(m, time.Now())
	apiJSON(w, 200, v)
}

// checkLifecycle validates the update target and expiry of a publish before
// any bytes are processed.
// An update target of another account is "release not found", like an unknown one.
func (a *apiServer) checkLifecycle(meta uploadMetadata, account string) (int, string) {
	if meta.Token != "" {
		if !validToken(meta.Token) {
			return 400, "invalid release token"
		}
		if m, e := a.s.info(meta.Token); e != nil || m.account() != account {
			return 404, "release not found"
		}
	}
	if _, _, ok := a.expiresAt(meta.ExpiresInDays, meta.Token != "", time.Now()); !ok {
		return 400, "expires_in_days must be an integer from 0 to 3650"
	}
	return 0, ""
}

// diskReport is the data filesystem as the publish paths see it, so an agent
// can tell whether an upload fits before sending it.
type diskReport struct {
	FreeBytes                 uint64  `json:"free_bytes"`
	TotalBytes                uint64  `json:"total_bytes"`
	FreeInodes                *uint64 `json:"free_inodes"`
	ReserveBytes              uint64  `json:"reserve_bytes"`
	AvailableBytes            uint64  `json:"available_bytes"`
	LargestFileUploadBytes    int64   `json:"largest_file_upload_bytes"`
	LargestArchiveUploadBytes int64   `json:"largest_archive_upload_bytes"`
	InlinePublishOK           bool    `json:"inline_publish_ok"`
}

// diskReportFor applies the same rules as diskOK: a single-file upload needs
// five times its size above the reserve (uploadReserve), an archive upload
// its size plus four times max_extract_bytes, an inline MCP publish its fixed
// worst case. Too few free inodes make every publish impossible.
func diskReportFor(st syscall.Statfs_t, cfg, inline apiConfig) diskReport {
	r := diskReport{ReserveBytes: cfg.MinFreeBytes}
	if st.Bsize <= 0 {
		return r
	}
	b := uint64(st.Bsize)
	mul := func(n uint64) uint64 {
		if n > ^uint64(0)/b {
			return ^uint64(0)
		}
		return n * b
	}
	r.FreeBytes, r.TotalBytes = mul(st.Bavail), mul(st.Blocks)
	if st.Files > 0 {
		free := st.Ffree
		r.FreeInodes = &free
	}
	if r.FreeBytes > cfg.MinFreeBytes {
		r.AvailableBytes = r.FreeBytes - cfg.MinFreeBytes
	}
	// Single-file uploads and archives use the configured entry budget for the inode check.
	if !apiDiskAvailable(st, cfg, 0) {
		return r
	}
	limit := uint64(cfg.MaxUploadBytes)
	r.LargestFileUploadBytes = int64(min(limit, r.AvailableBytes/5))
	if extract := 4 * uint64(cfg.MaxExtractBytes); r.AvailableBytes > extract {
		r.LargestArchiveUploadBytes = int64(min(limit, r.AvailableBytes-extract))
	}
	r.InlinePublishOK = apiDiskAvailable(st, inline, uint64(inline.MaxUploadBytes)+uint64(inline.MaxExtractBytes)*4)
	return r
}
func canonicalAPIPath(r *http.Request) bool {
	return r.URL.RawQuery == "" && !r.URL.ForceQuery && canonicalPath(r)
}
func canonicalPath(r *http.Request) bool {
	return r.URL.RawPath == "" && r.URL.EscapedPath() == r.URL.Path && path.Clean(r.URL.Path) == r.URL.Path && !strings.Contains(r.URL.Path, "\\")
}
func methodError(w http.ResponseWriter, id, allow string) {
	w.Header().Set("Allow", allow)
	apiError(w, 405, id, "method not allowed")
}
func (a *apiServer) view(m manifest) (releaseView, error) {
	p, e := a.s.policy(m.Token)
	// Every release a key sees is its own account's: the owner is not shown.
	m.Owner = ""
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
func (a *apiServer) diskOK(needed uint64, limits apiConfig) bool {
	var st syscall.Statfs_t
	if syscall.Statfs(a.incoming, &st) != nil {
		return false
	}
	return apiDiskAvailable(st, limits, needed)
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
	limits := a.mcpLimits()
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
	needed := uint64(limits.MaxUploadBytes) + uint64(limits.MaxExtractBytes)*4
	if !a.diskOK(needed, limits) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxUploadBytes+65536)
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
	if status, msg := a.checkLifecycle(meta, identity.Account); status != 0 {
		apiError(w, status, id, msg)
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
	h := spoolDigest(meta)
	reader := &archiveBudgetReader{r: p, left: limits.MaxUploadBytes, ctx: ctx}
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
	a.publishSpool(ctx, w, id, identity, key, meta, policy, f, hex.EncodeToString(h.Sum(nil)), limits)
}

// spoolDigest starts the idempotency digest: canonical metadata without the
// password (compared separately against its bcrypt hash), then the spool bytes.
func spoolDigest(meta uploadMetadata) hash.Hash {
	meta.Password = ""
	canonical, _ := json.Marshal(meta)
	h := sha256.New()
	h.Write(canonical)
	h.Write([]byte{0})
	return h
}

// publishSpool turns a fully received private spool into a release: the
// idempotency record, extraction, publisher validation and activation are the
// same for MCP publishes and ticket uploads. The caller holds the publisher slot.
func (a *apiServer) publishSpool(ctx context.Context, w http.ResponseWriter, id string, identity agentIdentity, key string, meta uploadMetadata, policy accessPolicy, f *os.File, digest string, limits apiConfig) {
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
		if currentErr != nil || current.account() != identity.Account {
			apiError(w, 409, id, "original release is no longer active")
			return
		}
		view, viewErr := a.view(current)
		if viewErr != nil {
			apiError(w, 500, id, "could not read release policy")
			return
		}
		view.Notice = expiryNotice(current, time.Now())
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
	// The target of an update must exist before extraction (it may have been
	// deleted since begin_upload), and the expiry must be valid.
	if status, msg := a.checkLifecycle(meta, identity.Account); status != 0 {
		apiError(w, status, id, msg)
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
	source, e := extractArtifact(ctx, f, dir, limits)
	if e != nil {
		a.bodyError(w, id, e)
		return
	}
	// Validate before persisting intent so a normal publisher validation refusal
	// is a correctable 422, not a permanently ambiguous idempotency key.
	plan, e := inspectSource(source)
	if e != nil {
		// Only the publisher's own refusals are echoed: they name a path relative
		// to the upload. Other failures could carry server paths.
		var refusal *sourceRefusal
		if errors.As(e, &refusal) {
			apiErrorDetail(w, 422, id, "publisher refused artifact", refusal.entry, refusal.reason)
		} else {
			apiError(w, 422, id, "publisher refused artifact")
		}
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
	if !a.diskOK(uint64(limits.MaxExtractBytes)*3, limits) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	record := apiReplay{Created: time.Now().UTC(), Digest: digest, State: "pending", PasswordHash: policy.PasswordHash}
	if e = a.writeReplay(rp, record); e != nil {
		apiError(w, 500, id, "could not persist publish intent")
		return
	}
	opts := releaseOptions{Label: meta.Label, SPA: meta.SPA, Policy: &policy, Replace: meta.Token, Owner: identity.Account}
	// An update without a password keeps the current access policy; removing
	// a password stays an explicit remove_password call.
	if meta.Token != "" && meta.Password == "" {
		opts.Policy = nil
	}
	opts.ExpiresAt, opts.KeepExpiry, _ = a.expiresAt(meta.ExpiresInDays, meta.Token != "", time.Now())
	m, _, e := a.s.publishRelease(ctx, source, opts)
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
	record.Release, e = a.view(m)
	if e != nil {
		if rw, ok := w.(*apiResponse); ok {
			rw.ambiguous = true
		}
		apiError(w, 500, id, "publish outcome is ambiguous; list your uploads before retrying")
		return
	}
	record.Release.Notice = expiryNotice(m, time.Now())
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
		var ae *archiveError
		switch {
		case errors.As(e, &ae) && ae.unsupported:
			apiErrorDetail(w, 400, id, "unsupported archive format", "", ae.reason)
		case errors.As(e, &ae) && ae.unsafe:
			apiErrorDetail(w, 400, id, "unsafe archive entry", ae.entry, ae.reason)
		case errors.As(e, &ae):
			apiErrorDetail(w, 400, id, "malformed archive", ae.entry, ae.reason)
		default:
			apiErrorDetail(w, 400, id, "malformed archive", "", "the request body or archive could not be read")
		}
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
// filename, not a request to decode twice. A raw "#" is never valid in a request
// target (RFC 9112 3.2): Caddy answers 400 before forwarding, and this rejects one
// that slips through (url.ParseRequestURI would keep it in the path or query).
// An encoded "%23" is an ordinary filename byte.
func authorizedURIToken(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 16384 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\x00#") {
		return "", false
	}
	u, e := url.ParseRequestURI(raw)
	if e != nil || u.IsAbs() || u.Host != "" {
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
		visitorError(w, 404, id, "link not found")
		return
	}
	// Expired releases are refused from the instant they expire, whether or
	// not the sweeper has deleted them yet.
	if m, e := a.s.info(token); e != nil || m.expired(time.Now()) {
		visitorError(w, 404, id, "link not found")
		return
	}
	p, e := a.s.policy(token)
	if e != nil {
		visitorError(w, 404, id, "link not found")
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
					visitorError(w, 429, id, "new viewer login attempts temporarily limited")
					return
				}
				select {
				case a.bcryptJobs <- struct{}{}:
					valid = p.Check(username, password)
					<-a.bcryptJobs
				default:
					visitorError(w, 429, id, "viewer authentication busy; retry shortly")
					return
				}
				if valid {
					a.rememberViewer(cacheKey)
				}
			}
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Basic realm="fserver-`+token+`", charset="UTF-8"`)
			visitorError(w, 401, id, "viewer authentication required")
			return
		}

		w.Header().Set("X-Fserver-Cache-Control", "private, no-store")
	} else {
		// Releases can be updated in place: caches may store public bytes but
		// must revalidate (a cheap 304 with ETag), so an update shows at once.
		w.Header().Set("X-Fserver-Cache-Control", "public, no-cache")
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

// expirySweepInterval is how often the serve command deletes expired
// releases. Visitors are refused at expiry regardless (authorize).
const expirySweepInterval = 10 * time.Minute

// sweepExpired deletes every release whose expires_at has passed and writes
// one audit line per deletion, in the same shape as request audit lines.
func (a *apiServer) sweepExpired(now time.Time) (int, error) {
	ms, err := a.s.list()
	if err != nil {
		auditLine("expire", 500, "", "")
		return 0, err
	}
	deleted := 0
	var errs []error
	for _, m := range ms {
		if !m.expired(now) {
			continue
		}
		ok, e := a.s.deleteExpired(m.Token, now)
		switch {
		case e != nil:
			auditLine("expire", 500, "", m.Token)
			errs = append(errs, e)
		case ok:
			auditLine("expire", 200, "", m.Token)
			deleted++
		}
	}
	return deleted, errors.Join(errs...)
}

// runExpirySweeper sweeps at start and then every interval until ctx ends.
func (a *apiServer) runExpirySweeper(ctx context.Context, interval time.Duration) {
	_, _ = a.sweepExpired(time.Now())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = a.sweepExpired(time.Now())
		}
	}
}

func auditLine(operation string, status int, agent, release string) {
	b, _ := json.Marshal(map[string]any{"ambiguous": false, "operation": operation, "status": status, "duration_ms": 0, "agent": agent, "release": release, "request_id": requestID()})
	_ = json.NewEncoder(os.Stderr).Encode(json.RawMessage(b))
}
