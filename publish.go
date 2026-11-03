package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Manifests count original files and bytes, not generated compression sidecars
// or the SPA marker. They intentionally contain no absolute source paths.
type manifest struct {
	Token            string    `json:"token"`
	URL              string    `json:"url"`
	Label            string    `json:"label"`
	CreatedAt        time.Time `json:"created_at"`
	SourceBasename   string    `json:"source_basename"`
	Files            int64     `json:"files"`
	Bytes            int64     `json:"bytes"`
	SPA              bool      `json:"spa"`
	OriginalFilename string    `json:"original_filename,omitempty"`
	// UpdatedAt is set when the content was replaced in place (same token).
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// ExpiresAt is when the expiry sweeper deletes the release; null never.
	// Releases from before expiry existed have no field and never expire.
	ExpiresAt *time.Time `json:"expires_at"`
	// Owner is the account that published the release, empty for the default
	// account (and every release from before accounts existed). Only keys of
	// that account can see or manage it. Never part of a release view.
	Owner string `json:"owner,omitempty"`
}

// account is the account that owns the release.
func (m manifest) account() string { return accountOf(m.Owner) }

// errNotOwner refuses an in-place update of another account's release.
var errNotOwner = errors.New("release belongs to another account")

// expired reports whether the release is past its expiry at now. Visitors are
// refused from that instant, before the sweeper deletes it.
func (m manifest) expired(now time.Time) bool {
	return m.ExpiresAt != nil && !now.Before(*m.ExpiresAt)
}

type store struct{ root, public, staging, manifests, trash, policies, baseURL string }

func newStore(root, base string) (*store, error) {
	if root == "" {
		root = "/var/lib/agent-fileserver"
	}
	if base == "" {
		return nil, fmt.Errorf("FSERVER_BASE_URL is required (for example https://files.example.com)")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(base, "\r\n\t ") {
		return nil, fmt.Errorf("FSERVER_BASE_URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	s := &store{root: root, public: filepath.Join(root, "public"), staging: filepath.Join(root, "staging"), manifests: filepath.Join(root, "manifests"), trash: filepath.Join(root, "trash"), policies: filepath.Join(root, "policies"), baseURL: strings.TrimRight(u.String(), "/")}
	if err = mkdirPrivateTree(root, 0755); err != nil {
		return nil, err
	}
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{{s.public, 0755}, {s.staging, 0700}, {s.manifests, 0700}, {s.trash, 0700}, {s.policies, 0700}} {
		if err = mkdirPrivateTree(d.path, d.mode); err != nil {
			return nil, err
		}
	}
	var dev uint64
	for i, p := range []string{s.public, s.staging, s.manifests, s.trash, s.policies} {
		st, e := os.Stat(p)
		if e != nil {
			return nil, e
		}
		d := uint64(st.Sys().(*syscall.Stat_t).Dev)
		if i == 0 {
			dev = d
		} else if dev != d {
			return nil, fmt.Errorf("public, staging, manifests, and trash must be on the same filesystem")
		}
	}
	return s, nil
}

func mkdirPrivateTree(path string, mode fs.FileMode) error {
	// Refuse symlinked configuration paths, including ancestors.
	if err := noSymlinkAncestors(path, true); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%q must be a real directory", path)
	}
	return os.Chmod(path, mode)
}

func noSymlinkAncestors(path string, allowMissing bool) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil && !(allowMissing && errors.Is(e, fs.ErrNotExist)) {
			return e
		}
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is not allowed", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

// All cooperating CLI processes serialize only their metadata/rename operations;
// validation, copying and compression may proceed concurrently.
func (s *store) lock() (func(), error) {
	return s.lockContext(context.Background())
}
func (s *store) lockContext(ctx context.Context) (func(), error) {
	p := filepath.Join(s.manifests, ".publish.lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("invalid publisher lock file")
	}
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func validToken(t string) bool {
	if len(t) != 22 {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validateName(name string, isDir bool) error {
	lower := strings.ToLower(name)
	reason := ""
	switch {
	case strings.HasPrefix(name, "."):
		reason = "dotfiles and dotdirectories (including .env files) are forbidden"
	case isDir && lower == "node_modules":
		reason = "node_modules must not be published"
	case strings.SplitN(lower, ".", 2)[0] == "credentials" || strings.SplitN(lower, ".", 2)[0] == "secrets":
		reason = "credential and secret files/directories are forbidden"
	case lower == "id_rsa" || lower == "id_dsa" || lower == "id_ecdsa" || lower == "id_ed25519":
		reason = "private keys are forbidden"
	}
	if reason == "" {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".map":
			reason = "source maps are forbidden"
		case ".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore":
			reason = "key and secret containers are forbidden"
		case ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar", ".cgi", ".fcgi", ".pl", ".pm", ".py", ".pyc", ".pyo", ".rb", ".sh", ".bash", ".zsh", ".ps1":
			reason = "server-side source/scripts are forbidden to prevent accidental source disclosure"
		}
	}
	if reason != "" {
		return &sourceRefusal{entry: name, reason: reason}
	}
	return nil
}

// sourceRefusal is a publisher policy refusal of one path relative to the
// source, safe to report back to the uploader with the reason.
type sourceRefusal struct{ entry, reason string }

func (e *sourceRefusal) Error() string {
	return fmt.Sprintf("refusing %q: %s; prepare a clean static output directory", e.entry, e.reason)
}

type sourceFile struct {
	rel  string
	info fs.FileInfo
}
type sourcePlan struct {
	root     *os.Root
	files    []sourceFile
	dirs     []string
	name     string
	single   bool
	hasIndex bool
}

func inspectSource(source string) (*sourcePlan, error) {
	return inspectSourceContext(context.Background(), source)
}
func inspectSourceContext(ctx context.Context, source string) (_ *sourcePlan, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	if err = noSymlinkAncestors(abs, false); err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		return nil, fmt.Errorf("source must be a regular file or directory, not %s", st.Mode())
	}
	p := &sourcePlan{name: filepath.Base(abs), single: !st.IsDir()}
	if err = validateName(p.name, st.IsDir()); err != nil {
		return nil, err
	}
	rootPath := abs
	if p.single {
		rootPath = filepath.Dir(abs)
	}
	p.root, err = os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			p.root.Close()
		}
	}()
	if p.single {
		ext := strings.ToLower(filepath.Ext(p.name))
		if ext == ".gz" || ext == ".br" {
			original := p.name[:len(p.name)-len(ext)]
			if _, e := p.root.Lstat(original); e == nil {
				return nil, &sourceRefusal{entry: p.name, reason: "precompressed sidecar next to its original; publish only the original, the server compresses it"}
			} else if !errors.Is(e, fs.ErrNotExist) {
				return nil, e
			}
		}
		p.files = []sourceFile{{p.name, st}}
		return p, nil
	}
	opened, err := p.root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(st, opened) {
		return nil, fmt.Errorf("source changed during validation")
	}
	var walk func(string) error
	walk = func(dir string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		// Open each validated directory as its own confined root. SameFile detects
		// directory substitutions before opening; descendants cannot escape it.
		before, e := p.root.Lstat(dir)
		if e != nil {
			return e
		}
		if !before.IsDir() {
			return fmt.Errorf("source directory %q changed during validation", dir)
		}
		dr, e := p.root.OpenRoot(dir)
		if e != nil {
			return e
		}
		defer dr.Close()
		after, e := dr.Stat(".")
		if e != nil {
			return e
		}
		if !os.SameFile(before, after) {
			return fmt.Errorf("source directory %q changed during validation", dir)
		}
		f, e := dr.Open(".")
		if e != nil {
			return e
		}
		entries, e := f.ReadDir(-1)
		f.Close()
		if e != nil {
			return e
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		names := map[string]bool{}
		for _, entry := range entries {
			names[entry.Name()] = true
		}
		for _, entry := range entries {
			if e := ctx.Err(); e != nil {
				return e
			}
			rel := filepath.Join(dir, entry.Name())
			info, e := dr.Lstat(entry.Name())
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return &sourceRefusal{entry: filepath.ToSlash(rel), reason: "symbolic links are not allowed"}
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return &sourceRefusal{entry: filepath.ToSlash(rel), reason: "special files (devices, sockets, FIFOs) are not allowed"}
			}
			if e = validateName(entry.Name(), info.IsDir()); e != nil {
				var refusal *sourceRefusal
				if errors.As(e, &refusal) {
					refusal.entry = filepath.ToSlash(rel)
				}
				return e
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if !info.IsDir() && (ext == ".gz" || ext == ".br") && names[entry.Name()[:len(entry.Name())-len(ext)]] {
				return &sourceRefusal{entry: filepath.ToSlash(rel), reason: "precompressed sidecar next to its original; publish only the original, the server compresses it"}
			}
			if info.IsDir() {
				p.dirs = append(p.dirs, rel)
				if e = walk(rel); e != nil {
					return e
				}
			} else {
				p.files = append(p.files, sourceFile{rel, info})
				if rel == "index.html" {
					p.hasIndex = true
				}
			}
		}
		return nil
	}
	if err = walk("."); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *store) publish(source, label string, spa bool) (manifest, string, error) {
	policy, err := makeAccessPolicy("")
	if err != nil {
		return manifest{}, "", err
	}
	return s.publishWithPolicy(source, label, spa, policy)
}
func (s *store) publishWithPolicyContext(ctx context.Context, source, label string, spa bool, policy accessPolicy) (manifest, string, error) {
	return s.publishRelease(ctx, source, releaseOptions{Label: label, SPA: spa, Policy: &policy})
}

// releaseOptions describe one publish. With Replace set, the content of that
// existing release is swapped in place: its token and root URL stay the same,
// a nil Policy keeps its access policy, an empty Label keeps its label and
// KeepExpiry keeps its expires_at.
type releaseOptions struct {
	Label      string
	SPA        bool
	Policy     *accessPolicy
	ExpiresAt  *time.Time
	KeepExpiry bool
	Replace    string
	// Owner is the publishing account; empty means the default account.
	Owner string
}

// stagedRelease is a validated, frozen private copy of a source, ready for the
// single activation (or exchange) rename.
type stagedRelease struct {
	dir, name        string
	single, hasIndex bool
	files, bytes     int64
}

// releaseURL is where m is served, built from the current base URL at
// response time. The url stored in a manifest is never read: after the
// domain changes it would hand out the old host. A single file is served at
// /TOKEN/NAME; a website, and a lone index.html (the static server already
// serves it at the release root), at /TOKEN/.
func (s *store) releaseURL(m manifest) string {
	u := s.baseURL + "/" + m.Token + "/"
	if m.OriginalFilename != "" && m.OriginalFilename != "index.html" {
		u += url.PathEscape(m.OriginalFilename)
	}
	return u
}

func (s *store) stageRelease(ctx context.Context, source string, spa bool) (_ *stagedRelease, err error) {
	p, err := inspectSourceContext(ctx, source)
	if err != nil {
		return nil, err
	}
	defer p.root.Close()
	if spa && (p.single || !p.hasIndex) {
		return nil, fmt.Errorf("--spa requires a directory with a root index.html")
	}
	stage, err := os.MkdirTemp(s.staging, "release-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			removeStage(stage)
		}
	}()
	r := &stagedRelease{dir: stage, name: p.name, single: p.single, hasIndex: p.hasIndex}
	for _, dir := range p.dirs {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = os.Mkdir(filepath.Join(stage, dir), 0700); err != nil {
			return nil, err
		}
	}
	for _, file := range p.files {
		if err = copySourceContext(ctx, p.root, file, filepath.Join(stage, file.rel)); err != nil {
			return nil, err
		}
		r.files++
		r.bytes += file.info.Size()
		if file.info.Size() >= 1024 && compressible(file.rel) {
			if err = s.compressContext(ctx, filepath.Join(stage, file.rel)); err != nil {
				return nil, fmt.Errorf("compress %q: %w", file.rel, err)
			}
		}
	}
	if spa {
		if err = os.WriteFile(filepath.Join(stage, ".fserver-spa"), nil, 0600); err != nil {
			return nil, err
		}
	}
	if err = freeze(stage); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *store) publishRelease(ctx context.Context, source string, o releaseOptions) (manifest, string, error) {
	m := manifest{}
	if err := ctx.Err(); err != nil {
		return m, "", err
	}
	if o.Policy == nil && o.Replace == "" {
		return m, "", fmt.Errorf("a new release needs an access policy")
	}
	if o.Policy != nil {
		if err := o.Policy.validate(); err != nil {
			return m, "", err
		}
	}
	if o.Replace != "" && !validToken(o.Replace) {
		return m, "", fmt.Errorf("invalid token: expected exactly 22 base64url characters")
	}
	r, err := s.stageRelease(ctx, source, o.SPA)
	if err != nil {
		return m, "", err
	}
	// After activation the stage path is gone; after an exchange it holds the
	// previous content. Either way it is private and removed here.
	defer removeStage(r.dir)
	unlock, err := s.lockContext(ctx)
	if err != nil {
		return m, "", err
	}
	defer unlock()
	if o.Replace != "" {
		m, err = s.replaceLocked(ctx, r, o)
	} else {
		m, err = s.activateLocked(ctx, r, o)
	}
	if err != nil {
		return m, "", err
	}
	warning := ""
	if !r.single && !r.hasIndex {
		warning = "no root index.html: the directory URL will return 404; individual file URLs remain usable"
	}
	return m, warning, nil
}

func (s *store) activateLocked(ctx context.Context, r *stagedRelease, o releaseOptions) (manifest, error) {
	m := manifest{Files: r.files, Bytes: r.bytes}
	token, err := s.availableToken()
	if err != nil {
		return m, err
	}
	m.Token = token
	m.Label = o.Label
	m.CreatedAt = time.Now().UTC()
	m.SourceBasename = r.name
	m.SPA = o.SPA
	m.ExpiresAt = o.ExpiresAt
	m.Owner = storedAccount(accountOf(o.Owner))
	if r.single {
		m.OriginalFilename = r.name
	}
	m.URL = s.releaseURL(m)
	if err = s.writeManifest(m); err != nil {
		return m, err
	}
	// Both private records are persisted before the only public activation rename.
	cleanupMetadata := func() error {
		return errors.Join(os.Remove(filepath.Join(s.manifests, token+".json")), os.Remove(filepath.Join(s.policies, token+".json")))
	}
	if err = writePrivateJSON(filepath.Join(s.policies, token+".json"), *o.Policy); err != nil {
		cleanupErr := os.Remove(filepath.Join(s.manifests, token+".json"))
		if removeErr := os.Remove(filepath.Join(s.policies, token+".json")); !errors.Is(removeErr, fs.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
		return m, errors.Join(err, cleanupErr)
	}
	if err = ctx.Err(); err != nil {
		return m, errors.Join(err, cleanupMetadata())
	}
	// Do not observe cancellation after activation begins: finish the bounded
	// rename/freeze transaction and report its known outcome to the caller.
	if err = os.Rename(r.dir, filepath.Join(s.public, token)); err != nil {
		cleanupErr := cleanupMetadata()
		return m, errors.Join(fmt.Errorf("activate release: %w", err), cleanupErr)
	}
	if err = os.Chmod(filepath.Join(s.public, token), 0555); err != nil {
		rollbackErr := os.Rename(filepath.Join(s.public, token), r.dir)
		if rollbackErr == nil {
			rollbackErr = cleanupMetadata()
		}
		return m, errors.Join(fmt.Errorf("freeze activated release %s: %w", m.URL, err), rollbackErr)
	}
	return m, nil
}

// replaceLocked swaps new content into an existing release. A new password is
// written before the swap, so a crash can leave the old content protected but
// never the new content public. The manifest is written before the swap and
// restored if the swap fails.
func (s *store) replaceLocked(ctx context.Context, r *stagedRelease, o releaseOptions) (manifest, error) {
	old, err := s.activeManifest(o.Replace)
	if err != nil {
		return manifest{}, err
	}
	// The API refuses this earlier; re-checked under the lock as a backstop.
	if old.account() != accountOf(o.Owner) {
		return manifest{}, errNotOwner
	}
	m := old
	m.Files, m.Bytes, m.SPA = r.files, r.bytes, o.SPA
	m.SourceBasename = r.name
	m.OriginalFilename = ""
	if r.single {
		m.OriginalFilename = r.name
	}
	m.URL = s.releaseURL(m)
	if o.Label != "" {
		m.Label = o.Label
	}
	if !o.KeepExpiry {
		m.ExpiresAt = o.ExpiresAt
	}
	now := time.Now().UTC()
	m.UpdatedAt = &now
	if err = ctx.Err(); err != nil {
		return old, err
	}
	if o.Policy != nil {
		if err = writePrivateJSON(filepath.Join(s.policies, old.Token+".json"), *o.Policy); err != nil {
			return old, err
		}
	}
	if err = s.writeManifest(m); err != nil {
		return old, err
	}
	if err = s.swapRelease(old.Token, r.dir); err != nil {
		return old, errors.Join(fmt.Errorf("swap release content: %w", err), s.writeManifest(old))
	}
	return m, nil
}

// renameExchange atomically exchanges two paths (Linux renameat2). Tests
// replace it to exercise the fallback for filesystems without the flag.
var renameExchange = func(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}

// swapRelease puts the frozen stage at public/token and the previous content
// at the stage path. Visitors see either the old or the new tree, never a
// mix within one file. Without RENAME_EXCHANGE it falls back to two renames,
// a sub-millisecond window in which the release returns 404.
func (s *store) swapRelease(token, stage string) error {
	live := filepath.Join(s.public, token)
	// Linux needs write permission on a directory that moves to a new parent.
	if err := os.Chmod(live, 0755); err != nil {
		return err
	}
	err := renameExchange(stage, live)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		err = swapByRename(live, stage)
	}
	if err != nil {
		return errors.Join(err, os.Chmod(live, 0555))
	}
	return os.Chmod(live, 0555)
}

func swapByRename(live, stage string) error {
	previous := stage + ".previous"
	if err := os.Rename(live, previous); err != nil {
		return err
	}
	if err := os.Rename(stage, live); err != nil {
		return errors.Join(err, os.Rename(previous, live))
	}
	return os.Rename(previous, stage)
}

// setExpiry changes when a release is deleted; nil means never.
func (s *store) setExpiry(token string, at *time.Time) (manifest, error) {
	unlock, err := s.lock()
	if err != nil {
		return manifest{}, err
	}
	defer unlock()
	m, err := s.activeManifest(token)
	if err != nil {
		return m, err
	}
	m.ExpiresAt = at
	return m, s.writeManifest(m)
}

func (s *store) availableToken() (string, error) {
	for i := 0; i < 100; i++ {
		t, e := newToken()
		if e != nil {
			return "", e
		}
		free := true
		for _, path := range []string{filepath.Join(s.public, t), filepath.Join(s.trash, t), filepath.Join(s.manifests, t+".json"), filepath.Join(s.policies, t+".json")} {
			_, e = os.Lstat(path)
			if e == nil {
				free = false
				break
			}
			if !errors.Is(e, fs.ErrNotExist) {
				return "", e
			}
		}
		if free {
			return t, nil
		}
	}
	return "", fmt.Errorf("could not allocate a fresh release token")
}

func copySource(root *os.Root, src sourceFile, dst string) error {
	return copySourceContext(context.Background(), root, src, dst)
}
func copySourceContext(ctx context.Context, root *os.Root, src sourceFile, dst string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	now, err := root.Lstat(src.rel)
	if err != nil {
		return err
	}
	if !now.Mode().IsRegular() || !os.SameFile(src.info, now) {
		return fmt.Errorf("source %q changed or became a symlink during copying", src.rel)
	}
	// O_NOFOLLOW also prevents a swapped-in symlink or FIFO from being opened.
	in, err := root.OpenFile(src.rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(src.info, opened) {
		return fmt.Errorf("source %q changed during copying", src.rel)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	// Copy only the validated size, then check for growth. This avoids a producer
	// appending forever without imposing an arbitrary legitimate-file size limit.
	n, err := io.CopyN(out, contextReader{ctx, in}, src.info.Size())
	if err != nil {
		return fmt.Errorf("copy %q: %w", src.rel, err)
	}
	var extra [1]byte
	count, e := in.Read(extra[:])
	if count != 0 || e != io.EOF {
		return fmt.Errorf("source %q changed size during copying", src.rel)
	}
	end, err := in.Stat()
	if err != nil {
		return err
	}
	if n != src.info.Size() || end.Size() != src.info.Size() || !end.ModTime().Equal(src.info.ModTime()) {
		return fmt.Errorf("source %q changed during copying", src.rel)
	}
	return out.Sync()
}

func compressible(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html", ".css", ".js", ".mjs", ".json", ".svg", ".txt", ".xml", ".csv", ".md", ".wasm":
		return true
	}
	return false
}

func (s *store) compress(src string) error { return s.compressContext(context.Background(), src) }
func (s *store) compressContext(ctx context.Context, src string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	original, err := os.Stat(src)
	if err != nil {
		return err
	}
	for _, kind := range []string{"gz", "br"} {
		tmp, err := os.CreateTemp(s.staging, "compress-")
		if err != nil {
			return err
		}
		name := tmp.Name()
		err = func() error {
			defer os.Remove(name)
			var e error
			if kind == "gz" {
				in, e := os.Open(src)
				if e != nil {
					tmp.Close()
					return e
				}
				z, e := gzip.NewWriterLevel(tmp, 6)
				if e != nil {
					in.Close()
					tmp.Close()
					return e
				}
				_, copyErr := io.Copy(z, contextReader{ctx, in})
				e = errors.Join(copyErr, z.Close(), in.Close())
			} else {
				cmd := exec.CommandContext(ctx, "brotli", "-q", "6", "-c", "--", src)
				cmd.WaitDelay = 2 * time.Second
				cmd.Stdout = tmp
				var diagnostic strings.Builder
				cmd.Stderr = &diagnostic
				e = cmd.Run()
				if ctx.Err() != nil {
					e = errors.Join(e, ctx.Err())
				}
				if e != nil {
					e = fmt.Errorf("brotli -q 6 failed (install the brotli executable): %w: %s", e, strings.TrimSpace(diagnostic.String()))
				}
			}
			if e == nil {
				e = tmp.Sync()
			}
			st, statErr := tmp.Stat()
			e = errors.Join(e, statErr, tmp.Close())
			if e != nil {
				return e
			}
			if st.Size() < original.Size() {
				return os.Rename(name, src+"."+kind)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func freeze(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0444)
		if d.IsDir() {
			mode = 0555
		}
		// Linux requires write permission on a moved directory when changing
		// its parent. Keep only the release root owner-writable until activation;
		// private staging is inaccessible to the HTTP server.
		if path == root {
			mode = 0755
		}
		return os.Chmod(path, mode)
	})
}
func removeStage(path string) {
	// Releases may have been frozen before a later commit failure. Restore only
	// directory write permissions so private staging can always be removed.
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if e == nil && d.IsDir() {
			return os.Chmod(p, 0700)
		}
		return e
	})
	_ = os.RemoveAll(path)
}

func (s *store) writeManifest(m manifest) (err error) {
	f, err := os.CreateTemp(s.manifests, ".manifest-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(m); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.manifests, m.Token+".json"))
}

func (s *store) activeManifest(token string) (manifest, error) {
	var m manifest
	if !validToken(token) {
		return m, fmt.Errorf("invalid token: expected exactly 22 base64url characters")
	}
	st, err := os.Lstat(filepath.Join(s.public, token))
	if errors.Is(err, fs.ErrNotExist) {
		return m, fmt.Errorf("release %s is not active", token)
	}
	if err != nil {
		return m, err
	}
	if !st.IsDir() {
		return m, fmt.Errorf("release %s is not a real directory", token)
	}
	p := filepath.Join(s.manifests, token+".json")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return m, err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&m); err != nil {
		return m, err
	}
	if m.Token != token {
		return m, fmt.Errorf("manifest token mismatch for %s", token)
	}
	m.URL = s.releaseURL(m)
	return m, nil
}
func (s *store) info(token string) (manifest, error) {
	unlock, err := s.lock()
	if err != nil {
		return manifest{}, err
	}
	defer unlock()
	return s.activeManifest(token)
}
func (s *store) list() ([]manifest, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	entries, err := os.ReadDir(s.public)
	if err != nil {
		return nil, err
	}
	result := []manifest{}
	for _, entry := range entries {
		if !validToken(entry.Name()) || !entry.IsDir() {
			continue
		}
		m, e := s.activeManifest(entry.Name())
		if e != nil {
			return nil, e
		}
		result = append(result, m)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].Token < result[j].Token
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}
func (s *store) unpublish(token string) (manifest, error) {
	unlock, err := s.lock()
	if err != nil {
		return manifest{}, err
	}
	defer unlock()
	m, err := s.activeManifest(token)
	if err != nil {
		return m, err
	}
	target := filepath.Join(s.trash, token)
	if _, err = os.Lstat(target); err == nil {
		return m, fmt.Errorf("trash destination already exists; refusing to overwrite")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return m, err
	}
	source := filepath.Join(s.public, token)
	if err = os.Chmod(source, 0755); err != nil {
		return m, err
	}
	if err = os.Rename(source, target); err != nil {
		return m, errors.Join(err, os.Chmod(source, 0555))
	}
	if err = os.Chmod(target, 0555); err != nil {
		rollbackErr := os.Rename(target, source)
		if rollbackErr == nil {
			rollbackErr = os.Chmod(source, 0555)
		}
		return m, errors.Join(err, rollbackErr)
	}
	return m, nil
}
