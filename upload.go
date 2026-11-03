package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Upload tickets let a client that holds a file (for example an AI host's
// code sandbox) publish it without the management key and without base64 in
// MCP JSON. The begin_upload MCP tool mints a ticket; PUT /_upload with
// "Authorization: Bearer upl_..." streams the raw bytes into the same release
// pipeline as MCP publishes. A ticket can do exactly one bounded publish.
const (
	uploadTicketPrefix  = "upl_"
	uploadTicketTTL     = 30 * time.Minute
	uploadReceiveWindow = 60 * time.Minute
	uploadPublishWindow = 15 * time.Minute
	uploadMaxPending    = 8
)

var errUploadTicketsFull = errors.New("too many pending upload tickets")

// uploadTicket is kept in memory only, keyed by the SHA-256 of the secret.
// The visitor password stays in memory for at most the ticket's lifetime and
// is never logged or written; the replay record stores only its bcrypt hash.
type uploadTicket struct {
	agentID, agentLabel, account string
	size                         int64
	sha256                       [32]byte
	filename, key                string
	meta                         uploadMetadata
	expires                      time.Time
}

type beginUploadRequest struct {
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	Filename       string `json:"filename,omitempty"`
	Label          string `json:"label,omitempty"`
	SPA            bool   `json:"spa,omitempty"`
	Password       string `json:"password,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`
	Token          string `json:"token,omitempty"`
	ExpiresInDays  *int   `json:"expires_in_days,omitempty"`
}

// uploadLimits are the extraction limits for one upload. A single file is
// wrapped in a one-entry tar, so its spool is the file plus tar framing and it
// unpacks to exactly its own size.
func (a *apiServer) uploadLimits(size int64, single bool) apiConfig {
	l := a.cfg
	if single {
		l.MaxUploadBytes = size + 1<<20
		l.MaxExtractBytes = size
	}
	return l
}

// uploadReserve is the free space an upload needs above MinFreeBytes: the
// spool plus extracted copy, publisher copy and compressed sidecars (worst case).
func uploadReserve(size int64, limits apiConfig) uint64 {
	return uint64(size) + 4*uint64(limits.MaxExtractBytes)
}

func validUploadFilename(n string) bool {
	if n == "" || len(n) > 255 || !utf8.ValidString(n) || n == "." || n == ".." ||
		strings.ContainsAny(n, "/\\") || validateName(n, false) != nil {
		return false
	}
	for _, c := range n {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// beginUpload is the in-process release-core endpoint behind the begin_upload
// MCP tool. It validates everything that can be checked before the bytes
// arrive, so a doomed upload fails before the client sends a gigabyte.
func (a *apiServer) beginUpload(w http.ResponseWriter, r *http.Request, id string, identity agentIdentity) {
	var req beginUploadRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if decodeJSON(r.Body, &req) != nil {
		apiError(w, 400, id, "invalid upload request")
		return
	}
	sum, err := hex.DecodeString(req.SHA256)
	if err != nil || len(sum) != sha256.Size || req.SHA256 != strings.ToLower(req.SHA256) {
		apiError(w, 400, id, "sha256 must be 64 lowercase hex characters")
		return
	}
	if req.Size < 1 || req.Size > a.cfg.MaxUploadBytes {
		apiError(w, 413, id, "size must be between 1 byte and the server's upload limit")
		return
	}
	if !validIdempotency(req.IdempotencyKey) {
		apiError(w, 400, id, "a URL-safe idempotency_key of 16 to 128 characters is required")
		return
	}
	if !apiValidLabel(req.Label) {
		apiError(w, 400, id, "invalid label")
		return
	}
	if _, err = makeAccessPolicy(req.Password); err != nil {
		apiError(w, 400, id, "password must be 8 to 72 UTF-8 bytes without control characters")
		return
	}
	meta := uploadMetadata{Label: req.Label, SPA: req.SPA, Password: req.Password, Token: req.Token, ExpiresInDays: req.ExpiresInDays}
	if status, msg := a.checkLifecycle(meta, identity.Account); status != 0 {
		apiError(w, status, id, msg)
		return
	}
	single := req.Filename != ""
	if single && !validUploadFilename(req.Filename) {
		apiError(w, 400, id, "filename must be a plain file name without slashes, dot prefix, secrets or server-side script extensions")
		return
	}
	if single && req.SPA {
		apiError(w, 422, id, "spa requires a website archive with a root index.html, not a single file")
		return
	}
	limits := a.uploadLimits(req.Size, single)
	if !a.diskOK(uploadReserve(req.Size, limits), limits) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	t := uploadTicket{agentID: identity.ID, agentLabel: identity.Label, account: identity.Account, size: req.Size, filename: req.Filename,
		key: req.IdempotencyKey, meta: meta}
	copy(t.sha256[:], sum)
	raw, expires, err := a.mintTicket(t, time.Now())
	if errors.Is(err, errUploadTicketsFull) {
		apiError(w, 429, id, "too many pending uploads; use or let them expire (30 minutes)")
		return
	}
	if err != nil {
		apiError(w, 500, id, "could not create upload ticket")
		return
	}
	target := a.s.baseURL + "/_upload"
	apiJSON(w, 201, map[string]any{
		"upload_url": target,
		"method":     "PUT",
		"headers":    map[string]string{"Authorization": "Bearer " + raw},
		"expires_at": expires.UTC().Format(time.RFC3339),
		"size":       req.Size,
		"sha256":     req.SHA256,
		"command":    "curl --fail-with-body -sS -T FILE -H 'Authorization: Bearer " + raw + "' " + target,
	})
}

func (a *apiServer) mintTicket(t uploadTicket, now time.Time) (string, time.Time, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", time.Time{}, err
	}
	raw := uploadTicketPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.tickets {
		if !now.Before(v.expires) {
			delete(a.tickets, k)
		}
	}
	if len(a.tickets) >= uploadMaxPending {
		return "", time.Time{}, errUploadTicketsFull
	}
	t.expires = now.Add(uploadTicketTTL)
	a.tickets[sha256.Sum256([]byte(raw))] = t
	return raw, t.expires, nil
}

// takeTicket consumes a ticket: it is gone after the first presentation,
// whatever happens next, so a leaked or replayed ticket is worthless.
func (a *apiServer) takeTicket(raw string, now time.Time) (uploadTicket, bool) {
	if !strings.HasPrefix(raw, uploadTicketPrefix) || len(raw) != len(uploadTicketPrefix)+43 {
		return uploadTicket{}, false
	}
	if _, err := base64.RawURLEncoding.DecodeString(raw[len(uploadTicketPrefix):]); err != nil {
		return uploadTicket{}, false
	}
	key := sha256.Sum256([]byte(raw))
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tickets[key]
	delete(a.tickets, key)
	return t, ok && now.Before(t.expires)
}

// uploadTicketHeader accepts only "Authorization: Bearer upl_...". Management
// keys are never accepted here, and X-Auth-Token is not an upload credential.
func uploadTicketHeader(r *http.Request) string {
	raw := r.Header.Get("Authorization")
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(raw, "Bearer "+uploadTicketPrefix) || len(raw) > 512 {
		return ""
	}
	return raw[len("Bearer "):]
}

func (a *apiServer) serveUpload(w http.ResponseWriter, r *http.Request, id string, agent *string) {
	if !canonicalAPIPath(r) {
		apiError(w, 404, id, "not found")
		return
	}
	// Any origin may present a ticket: the upload panel (an MCP Apps iframe
	// in the user's chat) runs on a host-chosen origin, possibly opaque
	// "null". The ticket is the only credential; no cookies or ambient
	// authority exist here, so CORS never lets a page do more than curl with
	// the same ticket. Credentials mode stays off (no Allow-Credentials).
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "X-Request-ID, Retry-After")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "PUT")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		h.Set("Allow", "PUT, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPut {
		methodError(w, id, "PUT, OPTIONS")
		return
	}
	now := time.Now()
	t, ok := a.takeTicket(uploadTicketHeader(r), now)
	if ok && !a.tokens.Active(t.agentID, now) {
		ok = false
	}
	if !ok {
		if !a.rate("auth:"+clientIP(r), 10, time.Minute, true) {
			apiError(w, 429, id, "too many authentication failures")
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		apiError(w, 401, id, "a valid, unused upload ticket from begin_upload is required")
		return
	}
	*agent = t.agentLabel
	if r.ContentLength > t.size {
		apiError(w, 413, id, "body is larger than the size declared to begin_upload")
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != t.size {
		apiError(w, 400, id, "body length differs from the size declared to begin_upload")
		return
	}
	if !a.rate("publish:"+t.agentID, a.cfg.PublishLimit, time.Hour, true) {
		apiError(w, 429, id, "publish attempt limit reached")
		return
	}
	select {
	case a.uploadSlot <- struct{}{}:
		defer func() { <-a.uploadSlot }()
	default:
		apiError(w, 429, id, "another upload is in progress; call begin_upload again later")
		return
	}
	// The service's global 180 s timeouts suit MCP; a gigabyte on a slow link
	// needs longer. Unsupported writers (tests) keep their own behaviour.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(now.Add(uploadReceiveWindow))
	_ = rc.SetWriteDeadline(now.Add(uploadReceiveWindow + uploadPublishWindow + time.Minute))
	single := t.filename != ""
	limits := a.uploadLimits(t.size, single)
	if err := a.cleanup(now); err != nil {
		apiError(w, 500, id, "could not maintain private API state")
		return
	}
	if !a.diskOK(uploadReserve(t.size, limits), limits) {
		apiError(w, 507, id, "insufficient free disk space")
		return
	}
	policy, err := makeAccessPolicy(t.meta.Password)
	if err != nil {
		apiError(w, 400, id, "invalid viewer password")
		return
	}
	f, err := os.CreateTemp(a.incoming, "api-upload-put-")
	if err != nil {
		apiError(w, 500, id, "could not stage upload")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	digest := spoolDigest(t.meta)
	content := sha256.New()
	spool := io.MultiWriter(f, digest)
	body := io.TeeReader(&archiveBudgetReader{r: r.Body, left: t.size, ctx: r.Context()}, content)
	var n int64
	if single {
		// Stream the file into a one-entry tar on the fly: no second copy, and
		// the publisher then treats it exactly like publish_files' single file.
		tw := tar.NewWriter(spool)
		if err = tw.WriteHeader(&tar.Header{Name: t.filename, Mode: 0600, Size: t.size, Typeflag: tar.TypeReg}); err == nil {
			n, err = io.Copy(tw, body)
		}
		if err == nil && n == t.size {
			err = tw.Close()
		}
	} else {
		n, err = io.Copy(spool, body)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		apiError(w, 408, id, "upload took too long")
		return
	}
	if err != nil {
		a.bodyError(w, id, err)
		return
	}
	if n != t.size {
		apiError(w, 400, id, "body is shorter than the size declared to begin_upload")
		return
	}
	if subtle.ConstantTimeCompare(content.Sum(nil), t.sha256[:]) != 1 {
		apiError(w, 400, id, "body does not match the sha256 declared to begin_upload")
		return
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		apiError(w, 500, id, "could not read staged upload")
		return
	}
	// Every byte has arrived. Publish even if the client now disconnects; it
	// can find the result with list_releases or an idempotent retry.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), uploadPublishWindow)
	defer cancel()
	select {
	case a.job <- struct{}{}:
		defer func() { <-a.job }()
	case <-ctx.Done():
		apiError(w, 429, id, "publisher busy; retry with a new ticket and the same idempotency_key")
		return
	}
	identity := agentIdentity{ID: t.agentID, Label: t.agentLabel, Account: t.account}
	a.publishSpool(ctx, w, id, identity, t.key, t.meta, policy, f, hex.EncodeToString(digest.Sum(nil)), limits)
}
