package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func securityTokens(t *testing.T) *tokenStore {
	t.Helper()
	store, err := newTokenStore(filepath.Join(t.TempDir(), "credentials", "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
func assertSecurityMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode %v, want %v", path, st.Mode().Perm(), want)
	}
}
func TestTokenStoreReadOnlyConstructionAndReads(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing", "tokens.json")
	store, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := store.List(); err != nil || len(list) != 0 {
		t.Fatalf("empty list: %v %v", list, err)
	}
	if _, err = store.Authenticate("absent", time.Now()); !errors.Is(err, errInvalidCredential) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Dir(path)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("reader mutated missing registry directory")
	}
	_, raw, err := store.Create("read-only", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err = os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Authenticate(raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.List(); err != nil {
		t.Fatal(err)
	}
	assertSecurityMode(t, dir, 0500)
	assertSecurityMode(t, path, 0600)
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("reader rewrote registry")
	}
	if _, err = os.Stat(path + ".lock"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("reader created a lock")
	}
}
func TestTokenStoreAuthExpiryRevocationAndSafeSummary(t *testing.T) {
	store := securityTokens(t)
	summary, raw, err := store.Create("cloud agent", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 || summary.ExpiresAt != nil || summary.Status != "active" {
		t.Fatalf("bad token summary: %+v", summary)
	}
	identity, err := store.Authenticate(raw, time.Now().AddDate(100, 0, 0))
	if err != nil || identity.Label != summary.Label || identity.ID == "" {
		t.Fatalf("auth: %+v %v", identity, err)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(raw)) {
		t.Fatal("plaintext bearer persisted")
	}
	reg, err := store.read()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID == reg.Tokens[0].Hash || identity.ID == raw {
		t.Fatal("identity exposes credential material")
	}
	encoded, _ := json.Marshal(identity)
	if bytes.Contains(encoded, []byte(identity.ID)) {
		t.Fatal("identity ID accidentally serialized")
	}
	encoded, _ = json.Marshal(summary)
	if bytes.Contains(encoded, []byte(reg.Tokens[0].Hash)) || bytes.Contains(encoded, []byte(raw)) {
		t.Fatal("unsafe summary")
	}
	assertSecurityMode(t, filepath.Dir(store.path), 0700)
	assertSecurityMode(t, store.path, 0600)
	assertSecurityMode(t, store.path+".lock", 0600)
	expiry, expiring, err := store.Create("expiring", 1)
	if err != nil {
		t.Fatal(err)
	}
	if expiry.ExpiresAt == nil {
		t.Fatal("no expiry")
	}
	if _, err = store.Authenticate(expiring, expiry.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{*expiry.ExpiresAt, expiry.ExpiresAt.Add(time.Second)} {
		if _, err = store.Authenticate(expiring, now); !errors.Is(err, errInvalidCredential) {
			t.Fatal("expired token authenticated")
		}
	}
	if err = store.Revoke(summary.Label); err != nil {
		t.Fatal(err)
	}
	other, err := newTokenStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bearer := range []string{raw, "", raw + "x", expiring} {
		if _, err = other.Authenticate(bearer, expiry.ExpiresAt.Add(time.Second)); !errors.Is(err, errInvalidCredential) || err.Error() != errInvalidCredential.Error() {
			t.Fatal("nonuniform auth error", err)
		}
	}
	if err = store.Revoke(summary.Label); err != nil {
		t.Fatal("repeated revoke should be idempotent", err)
	}
	if err = store.Revoke("unknown"); err == nil {
		t.Fatal("unknown revoke accepted")
	}
	if _, _, err = store.Create(summary.Label, 0); err == nil {
		t.Fatal("revoked label reused")
	}
	list, err := store.List()
	if err != nil || len(list) != 2 || list[0].Status != "revoked" {
		t.Fatalf("list: %+v %v", list, err)
	}
	for _, label := range []string{"", "bad\nlabel", "nul\x00label", string([]byte{0xff}), strings.Repeat("界", 201)} {
		if _, _, err = store.Create(label, 0); err == nil {
			t.Errorf("accepted label %q", label)
		}
	}
	for _, days := range []int{-1, 365001} {
		if _, _, err = store.Create("invalid-days", days); err == nil {
			t.Fatal("invalid lifetime accepted")
		}
	}
}
func TestTokenStoreConcurrentWritersAndImmediateRevocation(t *testing.T) {
	store := securityTokens(t)
	_, raw, err := store.Create("first", 0)
	if err != nil {
		t.Fatal(err)
	}
	const count = 20
	var wg sync.WaitGroup
	errs := make(chan error, count+1)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			other, e := newTokenStore(store.path)
			if e == nil {
				_, _, e = other.Create(fmt.Sprintf("agent-%02d", i), 0)
			}
			errs <- e
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if _, e := store.Authenticate(raw, time.Now()); e != nil {
				errs <- e
				return
			}
		}
		errs <- nil
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := store.List()
	if err != nil || len(list) != count+1 {
		t.Fatalf("lost writer: %d %v", len(list), err)
	}
	if err = store.Revoke("first"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Authenticate(raw, time.Now()); !errors.Is(err, errInvalidCredential) {
		t.Fatal("cached credential authenticated")
	}
}
func TestTokenStoreMalformedRegistryFailsClosed(t *testing.T) {
	store := securityTokens(t)
	_, raw, err := store.Create("fixture", 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var reg tokenRegistry
	if err = json.Unmarshal(data, &reg); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty": "{}", "null": "null", "no-version": `{"tokens":[]}`, "no-records": `{"version":1}`,
		"version": `{"version":2,"tokens":[]}`, "null-records": `{"version":1,"tokens":null}`,
		"unknown": `{"version":1,"tokens":[],"raw_token":"bad"}`, "duplicate-key": `{"version":2,"version":1,"tokens":[]}`,
		"trailing": string(data) + `{}`, "truncated": string(data[:len(data)/2]), "oversized": strings.Repeat(" ", 4<<20) + string(data),
	}
	changed := reg
	changed.Tokens = append([]tokenRecord{}, reg.Tokens...)
	changed.Tokens = append(changed.Tokens, changed.Tokens[0])
	encoded, _ := json.Marshal(changed)
	cases["duplicate-label-and-hash"] = string(encoded)
	changed.Tokens = append([]tokenRecord{}, reg.Tokens...)
	changed.Tokens[0].Hash = "bad"
	encoded, _ = json.Marshal(changed)
	cases["invalid-hash"] = string(encoded)
	changed.Tokens[0] = reg.Tokens[0]
	expiry := reg.Tokens[0].CreatedAt.Add(-time.Second)
	changed.Tokens[0].ExpiresAt = &expiry
	encoded, _ = json.Marshal(changed)
	cases["invalid-expiry"] = string(encoded)
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(store.path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Authenticate(raw, time.Now()); !errors.Is(err, errInvalidCredential) {
				t.Fatal("malformed registry authorized")
			}
			if _, err := newTokenStore(store.path); err == nil {
				t.Fatal("malformed registry accepted at construction")
			}
			if _, err := store.List(); err == nil {
				t.Fatal("malformed registry listed")
			}
			if _, _, err := store.Create("must-not-overwrite", 0); err == nil {
				t.Fatal("malformed registry overwritten")
			}
		})
	}
	if err = os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(store.path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Authenticate(raw, time.Now()); err == nil {
		t.Fatal("nonprivate registry authorized")
	}
	if err = os.Remove(store.path); err != nil {
		t.Fatal(err)
	}
	outside := put(t, t.TempDir(), "outside.json", data)
	if err = os.Symlink(outside, store.path); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Authenticate(raw, time.Now()); err == nil {
		t.Fatal("registry symlink followed")
	}
	if _, err = newTokenStore(store.path); err == nil {
		t.Fatal("registry symlink accepted")
	}
}
func TestAccessPolicyPasswordHashAndValidation(t *testing.T) {
	public, err := makeAccessPolicy("")
	if err != nil || public.Protected || public.PasswordHash != "" || !public.Check("", "") {
		t.Fatal("bad public policy", err)
	}
	password := "pässword-safe"
	p, err := makeAccessPolicy(password)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Protected || p.PasswordHash == password || strings.Contains(p.PasswordHash, password) {
		t.Fatal("plaintext password stored")
	}
	cost, err := bcrypt.Cost([]byte(p.PasswordHash))
	if err != nil || cost != bcrypt.DefaultCost {
		t.Fatal("wrong bcrypt cost", err)
	}
	again, err := makeAccessPolicy(password)
	if err != nil || again.PasswordHash == p.PasswordHash {
		t.Fatal("bcrypt salt not randomized", err)
	}
	for _, check := range []struct {
		user, password string
		want           bool
	}{{"viewer", password, true}, {"wrong", password, false}, {"viewer", "wrong", false}, {"", "", false}, {"viewer", strings.Repeat("a", 73), false}} {
		if p.Check(check.user, check.password) != check.want {
			t.Errorf("unexpected password check for username %q", check.user)
		}
	}
	for _, password := range []string{"short", strings.Repeat("a", 73), "password\n", "pass\x00word", string([]byte{'p', 'a', 's', 's', 'w', 'o', 'r', 0xff})} {
		if _, err = makeAccessPolicy(password); err == nil {
			t.Errorf("accepted invalid password %q", password)
		}
	}
	for _, password := range []string{strings.Repeat("a", 8), strings.Repeat("a", 72), "密码密码密码"} {
		if _, err = makeAccessPolicy(password); err != nil {
			t.Errorf("refused valid password: %v", err)
		}
	}
	invalid := []accessPolicy{{}, {UpdatedAt: time.Now(), PasswordHash: p.PasswordHash}, {Protected: true, UpdatedAt: time.Now()}, {Protected: true, UpdatedAt: time.Now(), PasswordHash: strings.Replace(p.PasswordHash, "$10$", "$31$", 1)}}
	for _, policy := range invalid {
		if policy.validate() == nil || policy.Check("viewer", password) {
			t.Fatal("invalid policy authorized")
		}
	}
}
func TestPolicyPersistedPrivateAndManifestHasNoPassword(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "document.txt", []byte("private"))
	p, err := makeAccessPolicy("viewer-password")
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := s.publishWithPolicy(src, "protected", false, p)
	if err != nil {
		t.Fatal(err)
	}
	assertSecurityMode(t, s.policies, 0700)
	assertSecurityMode(t, filepath.Join(s.policies, m.Token+".json"), 0600)
	got, err := s.policy(m.Token)
	if err != nil || !got.Check("viewer", "viewer-password") {
		t.Fatal("protected policy lost", err)
	}
	data, err := os.ReadFile(filepath.Join(s.manifests, m.Token+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("password")) || bytes.Contains(data, []byte(p.PasswordHash)) {
		t.Fatal("password leaked into manifest")
	}
	public, _ := makeAccessPolicy("")
	if err = s.setPolicy(m.Token, public); err != nil {
		t.Fatal(err)
	}
	got, err = s.policy(m.Token)
	if err != nil || got.Protected || got.PasswordHash != "" {
		t.Fatal("password not removed", err)
	}
	if err = s.setPolicy("../outside", public); err == nil {
		t.Fatal("invalid token accepted")
	}
	if err = s.setPolicy(strings.Repeat("a", 22), public); err == nil {
		t.Fatal("inactive token accepted")
	}
}
func TestPolicyMissingMalformedAndInsecureFailClosed(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "document.txt", []byte("fixture"))
	m, _, err := s.publish(src, "", false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.policies, m.Token+".json")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = s.policy(m.Token); err == nil {
		t.Fatal("missing policy accepted")
	}
	reopened, err := newStore(s.root, s.baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.policy(m.Token); err == nil {
		t.Fatal("startup silently migrated policy")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cases := []string{`{}`, `null`, `{"protected":false}`, `{"updated_at":"` + now + `"}`, `{"protected":null,"updated_at":"` + now + `"}`, `{"protected":false,"updated_at":"0001-01-01T00:00:00Z"}`, `{"protected":true,"updated_at":"` + now + `"}`, `{"protected":false,"password_hash":"secret","updated_at":"` + now + `"}`, `{"protected":false,"updated_at":"` + now + `","unexpected":1}`, `{"protected":true,"protected":false,"updated_at":"` + now + `"}`, strings.Repeat(" ", 4097)}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.policy(m.Token); err == nil {
				t.Fatal("malformed policy authorized")
			}
			if err := s.migratePolicies(); err == nil {
				t.Fatal("migration overwrote malformed policy")
			}
		})
	}
	public, _ := makeAccessPolicy("")
	if err = writePrivateJSON(path, public); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.policy(m.Token); err == nil {
		t.Fatal("nonprivate policy accepted")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := put(t, t.TempDir(), "policy.json", []byte(`{"protected":false,"updated_at":"`+now+`"}`))
	if err = os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err = s.policy(m.Token); err == nil {
		t.Fatal("policy symlink followed")
	}
}
func TestMigrationOnlyExplicitActiveMissingPolicies(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	protected, _ := makeAccessPolicy("protected-password")
	keep, _, err := s.publishWithPolicy(src, "keep", false, protected)
	if err != nil {
		t.Fatal(err)
	}
	missing, _, err := s.publish(src, "missing", false)
	if err != nil {
		t.Fatal(err)
	}
	inactive, _, err := s.publish(src, "inactive", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.unpublish(inactive.Token); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{missing.Token, inactive.Token} {
		if err = os.Remove(filepath.Join(s.policies, token+".json")); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.migratePolicies(); err != nil {
		t.Fatal(err)
	}
	if err = s.migratePolicies(); err != nil {
		t.Fatal("migration not idempotent", err)
	}
	got, err := s.policy(keep.Token)
	if err != nil || got.PasswordHash != protected.PasswordHash || !got.UpdatedAt.Equal(protected.UpdatedAt) {
		t.Fatal("migration changed protected release", err)
	}
	got, err = s.policy(missing.Token)
	if err != nil || got.Protected {
		t.Fatal("active legacy release not public", err)
	}
	if _, err = os.Stat(filepath.Join(s.policies, inactive.Token+".json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("migration touched trash policy")
	}
}
func TestProtectedActivationIsNeverVisibleWithoutPolicy(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	p, err := makeAccessPolicy("protected-password")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		for {
			select {
			case <-done:
				observed <- nil
				return
			default:
			}
			entries, err := os.ReadDir(s.public)
			if err != nil {
				observed <- err
				return
			}
			for _, entry := range entries {
				if !validToken(entry.Name()) {
					continue
				}
				got, err := s.policy(entry.Name())
				if err != nil {
					observed <- fmt.Errorf("visible release missing policy: %w", err)
					return
				}
				if !got.Protected || got.PasswordHash != p.PasswordHash {
					observed <- fmt.Errorf("visible release has wrong policy")
					return
				}
			}
		}
	}()
	for i := 0; i < 20; i++ {
		if _, _, err = s.publishWithPolicy(src, "protected", false, p); err != nil {
			close(done)
			<-observed
			t.Fatal(err)
		}
	}
	close(done)
	if err = <-observed; err != nil {
		t.Fatal(err)
	}
	requireEmpty(t, s.staging)
}
func TestPolicyWriteFailureRollsBackAllActivationState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root permission enforcement")
	}
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	p, err := makeAccessPolicy("protected-password")
	if err != nil {
		t.Fatal(err)
	}
	// An inaccessible private policy directory must never result in public bytes.
	if err = os.Chmod(s.policies, 0500); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.publishWithPolicy(src, "protected", false, p)
	if e := os.Chmod(s.policies, 0700); e != nil {
		t.Fatal(e)
	}
	if err == nil {
		t.Fatal("published despite failed policy persistence (run as non-root)")
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
	invalid := accessPolicy{Protected: true, UpdatedAt: time.Now()}
	if _, _, err = s.publishWithPolicy(src, "", false, invalid); err == nil {
		t.Fatal("invalid in-memory policy accepted")
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
}
func TestDeleteReleaseIsPermanentSelectedAndPreservesSoftTrash(t *testing.T) {
	s := testStore(t)
	src := sourceDir(t)
	put(t, src, "index.html", []byte("fixture"))
	put(t, src, "nested/deep/asset.txt", []byte("asset"))
	p, _ := makeAccessPolicy("protected-password")
	selected, _, err := s.publishWithPolicy(src, "selected", false, p)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := s.publishWithPolicy(src, "historical", false, p)
	if err != nil {
		t.Fatal(err)
	}
	active, _, err := s.publish(src, "keep active", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.unpublish(old.Token); err != nil {
		t.Fatal(err)
	}
	oldPolicy, err := os.ReadFile(filepath.Join(s.policies, old.Token+".json"))
	if err != nil {
		t.Fatal(err)
	}
	oldManifest, err := os.ReadFile(filepath.Join(s.manifests, old.Token+".json"))
	if err != nil {
		t.Fatal(err)
	}
	outside := put(t, t.TempDir(), "untouched.txt", []byte("outside"))
	if err = os.Chmod(filepath.Join(s.public, selected.Token), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Dir(outside), filepath.Join(s.public, selected.Token, "external")); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(s.public, selected.Token), 0555); err != nil {
		t.Fatal(err)
	}
	removed, err := s.deleteRelease(selected.Token)
	if err != nil || removed.Token != selected.Token {
		t.Fatalf("delete: %+v %v", removed, err)
	}
	for _, path := range []string{filepath.Join(s.public, selected.Token), filepath.Join(s.trash, selected.Token), filepath.Join(s.policies, selected.Token+".json"), filepath.Join(s.manifests, selected.Token+".json")} {
		if _, err = os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("selected release retained: %s %v", path, err)
		}
	}
	requireEmpty(t, s.staging)
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "outside" {
		t.Fatal("delete followed symlink", err)
	}
	if _, err = s.info(active.Token); err != nil {
		t.Fatal("unrelated active release lost", err)
	}
	for path, want := range map[string][]byte{filepath.Join(s.policies, old.Token+".json"): oldPolicy, filepath.Join(s.manifests, old.Token+".json"): oldManifest, filepath.Join(s.trash, old.Token, "nested/deep/asset.txt"): []byte("asset")} {
		got, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("historical data changed: %s %v", path, e)
		}
	}
	assertSecurityMode(t, filepath.Join(s.trash, old.Token), 0555)
	assertSecurityMode(t, filepath.Join(s.trash, old.Token, "nested/deep/asset.txt"), 0444)
	for _, token := range []string{old.Token, selected.Token, "../public", strings.Repeat("x", 22)} {
		if _, err = s.deleteRelease(token); err == nil {
			t.Fatal("deleted inactive or invalid token", token)
		}
	}
}
func TestDeleteCleanupFailureReportedAfterRemovalFromServing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root permission enforcement")
	}
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	m, _, err := s.publish(src, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(s.policies, 0500); err != nil {
		t.Fatal(err)
	}
	_, err = s.deleteRelease(m.Token)
	if e := os.Chmod(s.policies, 0700); e != nil {
		t.Fatal(e)
	}
	if err == nil {
		t.Fatal("incomplete private cleanup reported success (run as non-root)")
	}
	if _, err = os.Stat(filepath.Join(s.public, m.Token)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed delete remains served")
	}
}
func TestPublishingCancellationBeforeWorkAndDuringLock(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	p, _ := makeAccessPolicy("")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.publishWithPolicyContext(ctx, src, "", false, p); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled publish ran", err)
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
	unlock, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err = s.publishWithPolicyContext(deadline, src, "", false, p)
	unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("metadata lock ignored cancellation", err)
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
}
func TestPublishingCancellationKillsCompressionAndCleansStage(t *testing.T) {
	s := testStore(t)
	bin := t.TempDir()
	put(t, bin, "brotli", []byte("#!/bin/sh\nexec /bin/sleep 30\n"))
	if err := os.Chmod(filepath.Join(bin, "brotli"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	src := put(t, sourceDir(t), "file.txt", bytes.Repeat([]byte("compress me "), 500))
	p, _ := makeAccessPolicy("")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := s.publishWithPolicyContext(ctx, src, "", false, p)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("compressor ignored cancellation", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("compressor subprocess still running")
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
}
func TestContextCopyAndGzipRejectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (contextReader{ctx, strings.NewReader("data")}).Read(make([]byte, 4)); !errors.Is(err, context.Canceled) {
		t.Fatal("copy reader ignored cancellation", err)
	}
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", bytes.Repeat([]byte("data"), 1000))
	if err := s.compressContext(ctx, src); !errors.Is(err, context.Canceled) {
		t.Fatal("gzip accepted canceled context", err)
	}
	requireEmpty(t, s.staging)
}

func TestPrivateJSONRejectsCaseAliasesAndUnicodeFolds(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, key := range []string{"Protected", "PROTECTED", "proTected"} {
		body := []byte(`{"protected":true,"` + key + `":false,"updated_at":"` + now + `"}`)
		var p accessPolicy
		if err := strictJSON(body, &p); err == nil {
			t.Fatalf("policy case alias %q accepted", key)
		}
		body = []byte(`{"` + key + `":false,"updated_at":"` + now + `"}`)
		if err := strictJSON(body, &p); err == nil {
			t.Fatalf("lone policy case alias %q accepted", key)
		}
	}
	for _, body := range []string{
		`{"Version":1,"tokens":[]}`, `{"version":1,"Tokens":[]}`, `{"verſion":1,"tokens":[]}`,
		`{"version":1,"toKens":[]}`, `{"version":1,"tokens":[{"Label":"agent","hash":"bad","created_at":"` + now + `"}]}`,
		`{"version":1,"tokens":[{"label":"agent","Hash":"bad","created_at":"` + now + `"}]}`,
		`{"version":1,"tokens":[{"label":"agent","haſh":"bad","created_at":"` + now + `"}]}`,
	} {
		var reg tokenRegistry
		if err := strictJSON([]byte(body), &reg); err == nil {
			t.Fatalf("registry case alias accepted: %s", body)
		}
	}
}

// Cancellation injected exactly after durable private policy persistence proves
// the final pre-rename cancellation check also rolls both metadata files back.
type cancelAfterPolicyContext struct {
	context.Context
	policyDir string
}

func (c cancelAfterPolicyContext) Err() error {
	entries, err := os.ReadDir(c.policyDir)
	if err == nil && len(entries) > 0 {
		return context.Canceled
	}
	return nil
}
func TestPublishingCancellationAfterPolicyPersistenceBeforeActivation(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	policy, _ := makeAccessPolicy("")
	ctx := cancelAfterPolicyContext{Context: context.Background(), policyDir: s.policies}
	if _, _, err := s.publishWithPolicyContext(ctx, src, "", false, policy); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation ignored", err)
	}
	requireFailureClean(t, s)
	requireEmpty(t, s.policies)
}
func TestPolicyUpdatesAtomicUnderConcurrentReaders(t *testing.T) {
	s := testStore(t)
	src := put(t, sourceDir(t), "file.txt", []byte("fixture"))
	protected, _ := makeAccessPolicy("protected-password")
	public, _ := makeAccessPolicy("")
	m, _, err := s.publishWithPolicy(src, "", false, protected)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		for {
			select {
			case <-done:
				result <- nil
				return
			default:
			}
			p, e := s.policy(m.Token)
			if e != nil {
				result <- e
				return
			}
			if (p.Protected && p.PasswordHash != protected.PasswordHash) || (!p.Protected && p.PasswordHash != "") {
				result <- fmt.Errorf("torn policy")
				return
			}
		}
	}()
	for i := 0; i < 30; i++ {
		p := public
		if i%2 == 0 {
			p = protected
		}
		if err = s.setPolicy(m.Token, p); err != nil {
			close(done)
			<-result
			t.Fatal(err)
		}
	}
	close(done)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}
func TestPrivateJSONRejectsInvalidUTF8AndNullScalars(t *testing.T) {
	for _, body := range []string{`{"version":1,"tokens":[{"label":"` + string([]byte{0xff}) + `","hash":"bad"}]}`, `{"version":null,"tokens":[]}`} {
		var reg tokenRegistry
		if err := strictJSON([]byte(body), &reg); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}
