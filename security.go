package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Identity is deliberately distinct from both the bearer and its stored digest.
// ID is internal: never accidentally serialize the token lookup material.
type agentIdentity struct {
	ID    string `json:"-"`
	Label string `json:"label"`
}
type tokenSummary struct {
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Status    string     `json:"status"`
}
type tokenRecord struct {
	Label     string     `json:"label"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
type tokenRegistry struct {
	Version int           `json:"version"`
	Tokens  []tokenRecord `json:"tokens"`
}
type tokenStore struct{ path string }

var errInvalidCredential = errors.New("invalid credential")

// Construction is read-only, including when the registry does not yet exist.
// The API's mount of this path is intentionally read-only.
func newTokenStore(path string) (*tokenStore, error) {
	if path == "" {
		return nil, fmt.Errorf("token registry path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = noSymlinkAncestors(abs, true); err != nil {
		return nil, err
	}
	t := &tokenStore{path: abs}
	if _, err = t.read(); err != nil {
		return nil, err
	}
	return t, nil
}

func validLabel(label string) bool {
	if label == "" || !utf8.ValidString(label) || utf8.RuneCountInString(label) > 200 {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Check exact schema keys before Go's decoder, which otherwise accepts
// case-insensitive aliases (including Unicode folds) of sensitive fields.
// Missing required fields are separately validated by the policy/registry reader.
func strictJSON(data []byte, out any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid JSON UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(reflect.Type, int) error
	value = func(typ reflect.Type, depth int) error {
		if depth > 64 {
			return fmt.Errorf("JSON nesting exceeds limit")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			if typ.Kind() != reflect.Pointer {
				return fmt.Errorf("unexpected JSON null")
			}
			return nil
		}
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			if typ.Kind() != reflect.Struct {
				return fmt.Errorf("unexpected JSON object")
			}
			fields := map[string]reflect.Type{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				key := strings.Split(f.Tag.Get("json"), ",")[0]
				if f.IsExported() && key != "-" {
					if key == "" {
						key = f.Name
					}
					fields[key] = f.Type
				}
			}
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				field, known := fields[k]
				if !ok || !known || seen[k] {
					return fmt.Errorf("unknown or duplicate JSON field")
				}
				seen[k] = true
				if err = value(field, depth+1); err != nil {
					return err
				}
			}
		case '[':
			if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Array {
				return fmt.Errorf("unexpected JSON array")
			}
			for d.More() {
				if err = value(typ.Elem(), depth+1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return fmt.Errorf("JSON destination must be a pointer")
	}
	if err := value(typ.Elem(), 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func readPrivateJSON(path string, limit int64, out any) error {
	if err := noSymlinkAncestors(path, false); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > limit {
		return fmt.Errorf("invalid private state file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("private state exceeds size limit")
	}
	return strictJSON(data, out)
}

func (t *tokenStore) read() (tokenRegistry, error) {
	reg := tokenRegistry{}
	err := readPrivateJSON(t.path, 4<<20, &reg)
	if errors.Is(err, fs.ErrNotExist) {
		return tokenRegistry{Version: 1, Tokens: []tokenRecord{}}, nil
	}
	if err != nil {
		return reg, err
	}
	if reg.Version != 1 || reg.Tokens == nil || len(reg.Tokens) > 10000 {
		return reg, fmt.Errorf("invalid token registry")
	}
	labels, hashes := map[string]bool{}, map[string]bool{}
	for _, r := range reg.Tokens {
		hash, e := hex.DecodeString(r.Hash)
		if !validLabel(r.Label) || labels[r.Label] || e != nil || len(hash) != sha256.Size || r.Hash != strings.ToLower(r.Hash) || hashes[r.Hash] || r.CreatedAt.IsZero() {
			return reg, fmt.Errorf("invalid token registry record")
		}
		if (r.ExpiresAt != nil && !r.ExpiresAt.After(r.CreatedAt)) || (r.RevokedAt != nil && r.RevokedAt.Before(r.CreatedAt)) {
			return reg, fmt.Errorf("invalid token registry timestamps")
		}
		labels[r.Label], hashes[r.Hash] = true, true
	}
	return reg, nil
}

func (t *tokenStore) Authenticate(raw string, now time.Time) (agentIdentity, error) {
	reg, err := t.read()
	if err != nil {
		return agentIdentity{}, errInvalidCredential
	}
	digest := sha256.Sum256([]byte(raw))
	var identity agentIdentity
	found := false
	for _, r := range reg.Tokens {
		stored, _ := hex.DecodeString(r.Hash)
		match := subtle.ConstantTimeCompare(stored, digest[:])
		if match == 1 && r.RevokedAt == nil && (r.ExpiresAt == nil || now.Before(*r.ExpiresAt)) {
			id := sha256.Sum256(append([]byte("fserver-agent-identity:"), stored...))
			identity = agentIdentity{ID: hex.EncodeToString(id[:]), Label: r.Label}
			found = true
		}
	}
	if !found {
		return agentIdentity{}, errInvalidCredential
	}
	return identity, nil
}
func summarizeToken(r tokenRecord, now time.Time) tokenSummary {
	status := "active"
	if r.RevokedAt != nil {
		status = "revoked"
	} else if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
		status = "expired"
	}
	return tokenSummary{Label: r.Label, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt, Status: status}
}
func (t *tokenStore) List() ([]tokenSummary, error) {
	reg, err := t.read()
	if err != nil {
		return nil, err
	}
	out := make([]tokenSummary, 0, len(reg.Tokens))
	now := time.Now().UTC()
	for _, r := range reg.Tokens {
		out = append(out, summarizeToken(r, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}
func (t *tokenStore) writerLock() (func(), error) {
	dir := filepath.Dir(t.path)
	if err := noSymlinkAncestors(dir, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("token registry directory must be private (0700)")
	}
	f, err := os.OpenFile(t.path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, fmt.Errorf("invalid token registry lock")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func (t *tokenStore) Create(label string, days int) (tokenSummary, string, error) {
	if !validLabel(label) || days < 0 || days > 365000 {
		return tokenSummary{}, "", fmt.Errorf("invalid token label or lifetime")
	}
	unlock, err := t.writerLock()
	if err != nil {
		return tokenSummary{}, "", err
	}
	defer unlock()
	reg, err := t.read()
	if err != nil {
		return tokenSummary{}, "", err
	}
	for _, r := range reg.Tokens {
		if r.Label == label {
			return tokenSummary{}, "", fmt.Errorf("token label already exists")
		}
	}
	if len(reg.Tokens) >= 10000 {
		return tokenSummary{}, "", fmt.Errorf("token registry is full")
	}
	raw := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, raw); err != nil {
		return tokenSummary{}, "", err
	}
	bearer := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(bearer))
	now := time.Now().UTC()
	r := tokenRecord{Label: label, Hash: hex.EncodeToString(hash[:]), CreatedAt: now}
	if days > 0 {
		expiry := now.AddDate(0, 0, days)
		r.ExpiresAt = &expiry
	}
	reg.Tokens = append(reg.Tokens, r)
	if err = t.write(reg, true); err != nil {
		return tokenSummary{}, "", err
	}
	return summarizeToken(r, now), bearer, nil
}
func (t *tokenStore) Revoke(label string) error {
	unlock, err := t.writerLock()
	if err != nil {
		return err
	}
	defer unlock()
	reg, err := t.read()
	if err != nil {
		return err
	}
	for i := range reg.Tokens {
		if reg.Tokens[i].Label == label {
			if reg.Tokens[i].RevokedAt != nil {
				return nil
			}
			now := time.Now().UTC()
			reg.Tokens[i].RevokedAt = &now
			return t.write(reg, false)
		}
	}
	return fmt.Errorf("token label not found")
}

// Leave space for revocation timestamps when admitting new records, so filling
// the registry cannot make an ordinary later revocation exceed the read bound.
func (t *tokenStore) write(reg tokenRegistry, reserveRevocations bool) error {
	encoded, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	reserved := 0
	if reserveRevocations {
		for _, r := range reg.Tokens {
			if r.RevokedAt == nil {
				reserved += 64
			}
		}
	}
	if len(encoded)+1+reserved > 4<<20 {
		return fmt.Errorf("token registry is full")
	}
	return writePrivateJSON(t.path, reg)
}

// Private writes are durable-before-rename and atomically replace only one file.
func writePrivateJSON(path string, value any) (err error) {
	if err = noSymlinkAncestors(path, true); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(value); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

type accessPolicy struct {
	Protected    bool      `json:"protected"`
	PasswordHash string    `json:"password_hash,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func makeAccessPolicy(password string) (accessPolicy, error) {
	p := accessPolicy{UpdatedAt: time.Now().UTC()}
	if password == "" {
		return p, nil
	}
	if !utf8.ValidString(password) || len(password) < 8 || len(password) > 72 {
		return accessPolicy{}, fmt.Errorf("password must be 8–72 UTF-8 bytes without control characters")
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return accessPolicy{}, fmt.Errorf("password must not contain control characters")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return accessPolicy{}, err
	}
	p.Protected = true
	p.PasswordHash = string(hash)
	return p, nil
}
func (p accessPolicy) validate() error {
	if p.UpdatedAt.IsZero() {
		return fmt.Errorf("policy timestamp is required")
	}
	if !p.Protected {
		if p.PasswordHash != "" {
			return fmt.Errorf("public policy contains a password hash")
		}
		return nil
	}
	h := p.PasswordHash
	if len(h) != 60 || !(strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$")) {
		return fmt.Errorf("invalid password hash")
	}
	for _, c := range h[7:] {
		if !(c == '.' || c == '/' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return fmt.Errorf("invalid password hash")
		}
	}
	cost, err := bcrypt.Cost([]byte(h))
	if err != nil || cost != bcrypt.DefaultCost {
		return fmt.Errorf("invalid password hash cost")
	}
	return nil
}
func (p accessPolicy) Check(username, password string) bool {
	if p.validate() != nil {
		return false
	}
	if !p.Protected {
		return true
	}
	if username != "viewer" || len(password) > 72 || !utf8.ValidString(password) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(p.PasswordHash), []byte(password)) == nil
}
func (s *store) policy(token string) (accessPolicy, error) {
	if !validToken(token) {
		return accessPolicy{}, fmt.Errorf("invalid release token")
	}
	st, err := os.Lstat(filepath.Join(s.public, token))
	if err != nil {
		return accessPolicy{}, err
	}
	if !st.IsDir() {
		return accessPolicy{}, fmt.Errorf("release is not active")
	}
	return s.readPolicy(token)
}
func (s *store) readPolicy(token string) (accessPolicy, error) {
	var raw struct {
		Protected    *bool      `json:"protected"`
		PasswordHash string     `json:"password_hash,omitempty"`
		UpdatedAt    *time.Time `json:"updated_at"`
	}
	if err := readPrivateJSON(filepath.Join(s.policies, token+".json"), 4096, &raw); err != nil {
		return accessPolicy{}, err
	}
	if raw.Protected == nil || raw.UpdatedAt == nil {
		return accessPolicy{}, fmt.Errorf("missing policy fields")
	}
	p := accessPolicy{Protected: *raw.Protected, PasswordHash: raw.PasswordHash, UpdatedAt: *raw.UpdatedAt}
	if err := p.validate(); err != nil {
		return accessPolicy{}, err
	}
	return p, nil
}
func (s *store) setPolicy(token string, p accessPolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = s.activeManifest(token); err != nil {
		return err
	}
	return writePrivateJSON(filepath.Join(s.policies, token+".json"), p)
}

// Explicit owner-local migration only. Existing policies are never overwritten,
// especially malformed ones; partial migration remains fail-closed on failure.
func (s *store) migratePolicies() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := os.ReadDir(s.public)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		token := entry.Name()
		if !validToken(token) || !entry.IsDir() {
			continue
		}
		if _, err = s.activeManifest(token); err != nil {
			return err
		}
		if _, err = s.readPolicy(token); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		p, _ := makeAccessPolicy("")
		if err = writePrivateJSON(filepath.Join(s.policies, token+".json"), p); err != nil {
			return err
		}
	}
	return nil
}
func (s *store) publishWithPolicy(source, label string, spa bool, p accessPolicy) (manifest, string, error) {
	return s.publishWithPolicyContext(context.Background(), source, label, spa, p)
}

// Removal is selected-release-only. Historical soft-unpublish trash is untouched.
// A cleanup error is reported after removal from serving, never hidden as success.
func (s *store) deleteRelease(token string) (manifest, error) {
	unlock, err := s.lock()
	if err != nil {
		return manifest{}, err
	}
	defer unlock()
	m, err := s.activeManifest(token)
	if err != nil {
		return m, err
	}
	container, err := os.MkdirTemp(s.staging, "delete-"+token+"-")
	if err != nil {
		return m, err
	}
	source := filepath.Join(s.public, token)
	target := filepath.Join(container, "release")
	if err = os.Chmod(source, 0755); err != nil {
		_ = os.Remove(container)
		return m, err
	}
	if err = os.Rename(source, target); err != nil {
		_ = os.Remove(container)
		return m, errors.Join(err, os.Chmod(source, 0555))
	}
	treeErr := removePrivateTree(container)
	manifestErr := os.Remove(filepath.Join(s.manifests, token+".json"))
	policyErr := os.Remove(filepath.Join(s.policies, token+".json"))
	// Missing policy is already fail-closed and must not prevent deleting a legacy
	// or damaged release. Every other cleanup error remains visible.
	if errors.Is(policyErr, fs.ErrNotExist) {
		policyErr = nil
	}
	return m, errors.Join(treeErr, manifestErr, policyErr)
}
func removePrivateTree(path string) error {
	if err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// Every copy read checks cancellation, including gzip input (which runs in Go).
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
