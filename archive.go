package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var errArchiveLimit = errors.New("archive limit exceeded")
var errUnsafeArchive = errors.New("invalid or unsafe archive")

// archiveError says why an archive was refused, so an agent can fix its
// packaging instead of bisecting. It always matches errUnsafeArchive. entry is
// the member name exactly as the uploader's own archive spelled it (bounded,
// never file content); it is empty when the archive as a whole is malformed.
type archiveError struct {
	entry, reason       string
	unsafe, unsupported bool
}

func (e *archiveError) Error() string {
	if e.unsafe {
		return fmt.Sprintf("unsafe archive entry %q: %s", e.entry, e.reason)
	}
	if e.entry != "" {
		return fmt.Sprintf("malformed archive entry %q: %s", e.entry, e.reason)
	}
	return "malformed archive: " + e.reason
}
func (e *archiveError) Unwrap() error { return errUnsafeArchive }

// maxReportedEntry bounds an echoed member name; names may be up to 1 KiB or
// more in a hostile archive and the reason must stay readable.
const maxReportedEntry = 256

func unsafeEntry(name, reason string) error {
	if len(name) > maxReportedEntry {
		name = name[:maxReportedEntry]
		for len(name) > 0 && !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
		name += "..."
	}
	return &archiveError{entry: name, reason: reason, unsafe: true}
}
func malformedArchive(reason string) error { return &archiveError{reason: reason} }

// unsupportedFormat names a recognised but unsupported container so the agent
// can repack instead of guessing. It runs only after the first tar header has
// already failed to parse, so it can sharpen an error but never refuse a valid
// archive (a tar header starts with a file name, which may be "BZh..."). No
// decoder runs, so these formats add no parsing surface.
func unsupportedFormat(magic []byte) error {
	for _, f := range []struct{ name, magic string }{
		{"xz", "\xfd7zXZ\x00"}, {"zstd", "\x28\xb5\x2f\xfd"}, {"bzip2", "BZh"},
		{"7z", "7z\xbc\xaf\x27\x1c"}, {"rar", "Rar!\x1a\x07"}, {"lzip", "LZIP"}, {"lz4", "\x04\x22\x4d\x18"},
	} {
		if strings.HasPrefix(string(magic), f.magic) {
			return &archiveError{unsupported: true, reason: "detected " + f.name + "; only ZIP, tar and tar.gz are supported"}
		}
	}
	return nil
}

// malformedEntry is structural damage that can be pinned to one member.
func malformedEntry(name, reason string) error {
	e := unsafeEntry(name, reason).(*archiveError)
	e.unsafe = false
	return e
}

type archiveBudgetReader struct {
	r          io.Reader
	left, read int64
	ctx        context.Context
}

func (r *archiveBudgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.left < 0 {
		return 0, errArchiveLimit
	}
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, e := r.r.Read(p)
	r.left -= int64(n)
	r.read += int64(n)
	if r.left < 0 {
		return n, errArchiveLimit
	}
	return n, e
}

// extractArtifact accepts flat or single-wrapper tar, tar.gz and ZIP.
// dst must be a newly created private directory. The returned operand still
// requires the shared publisher's validation; extraction is not activation.
func extractArtifact(ctx context.Context, input io.Reader, dst string, cfg apiConfig) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	limit := cfg.MaxUploadBytes
	if limit <= 0 {
		limit = 100 << 20
	}
	// API uploads are already private disk spools. Preserve ReaderAt access and
	// the caller's current offset instead of copying a second 100 MiB spool.
	var random io.ReaderAt
	var size int64
	if f, ok := input.(*os.File); ok {
		st, err := f.Stat()
		if err != nil {
			return "", err
		}
		if st.Mode().IsRegular() {
			offset, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return "", err
			}
			size = st.Size() - offset
			if size < 0 {
				return "", errUnsafeArchive
			}
			if size > limit {
				return "", errArchiveLimit
			}
			section := io.NewSectionReader(f, offset, size)
			input, random = section, section
		}
	}
	wire := bufio.NewReader(&archiveBudgetReader{r: input, left: limit, ctx: ctx})
	magic, err := wire.Peek(4)
	if err != nil && err != io.EOF {
		return "", err
	}
	if isZIPMagic(magic) {
		if random == nil {
			// Generic readers (including tests) get a bounded private disk
			// fallback, never an unbounded in-memory ReadAll.
			f, err := os.CreateTemp(filepath.Dir(dst), ".archive-zip-")
			if err != nil {
				return "", err
			}
			defer f.Close()
			defer os.Remove(f.Name())
			size, err = io.Copy(f, wire)
			if err != nil {
				return "", err
			}
			random = f
		}
		return extractZIP(ctx, random, size, dst, cfg)
	}
	return extractTar(ctx, wire, dst, cfg)
}

// Tar follows the ZIP layout rules: a flat site, or one wrapper directory that
// is unwrapped once. One leading "./" (as written by "tar -C dir -czf x .") is
// dropped; the bare "./" entry names the archive root itself.
func extractTar(ctx context.Context, wire *bufio.Reader, dst string, cfg apiConfig) (string, error) {
	var stream io.Reader = wire
	var gz *gzip.Reader
	prefix, _ := wire.Peek(8)
	prefix = bytes.Clone(prefix)
	magic, _ := wire.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		var err error
		gz, err = gzip.NewReader(wire)
		if err != nil {
			return "", malformedArchive("invalid gzip header")
		}
		defer gz.Close()
		gz.Multistream(false)
		stream = gz
	}
	// Physical headers, extended records and padding count too. File payload has
	// its separate stricter budget, so metadata cannot be used as a gzip bomb.
	bounded := &archiveBudgetReader{r: stream, left: cfg.MaxExtractBytes + int64(cfg.MaxEntries)*2048 + 1048576, ctx: ctx}
	tr := tar.NewReader(bounded)
	seen := map[string]byte{}
	roots := map[string]bool{}
	files := 0
	count := 0
	objects := 0
	var total int64
	for {
		before := bounded.read
		h, err := tr.Next()
		if err == io.EOF {
			// archive/tar tolerates a missing end marker; our wire contract does not.
			if bounded.read-before < 1024 {
				return "", malformedArchive("tar end-of-archive marker missing or truncated")
			}
			break
		}
		if err != nil {
			if errors.Is(err, errArchiveLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			if count == 0 {
				if gz == nil {
					if e := unsupportedFormat(prefix); e != nil {
						return "", e
					}
				}
				return "", malformedArchive("not a ZIP, tar or tar.gz archive")
			}
			return "", malformedArchive("corrupt or truncated tar header")
		}
		count++
		if count > cfg.MaxEntries {
			return "", errArchiveLimit
		}
		raw := h.Name
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return "", unsafeEntry(raw, tarTypeReason(h.Typeflag))
		}
		for key := range h.PAXRecords {
			if strings.Contains(strings.ToLower(key), "sparse") || key == "SCHILY.realsize" {
				return "", unsafeEntry(raw, "sparse files are not supported")
			}
		}
		name := raw
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
			if name == "." {
				if h.Size != 0 {
					return "", unsafeEntry(raw, "directory entry has data")
				}
				continue // "./": the archive root, which always exists.
			}
		}
		name = strings.TrimPrefix(name, "./")
		if !utf8.ValidString(name) || len(name) == 0 || len(name) > 1024 || strings.ContainsAny(name, "\\\x00\r\n") || strings.HasPrefix(name, "/") {
			return "", unsafeEntry(raw, "invalid path: absolute, empty, too long, not UTF-8, or contains a backslash or control character")
		}
		parts := strings.Split(name, "/")
		if len(parts) > 32 {
			return "", errArchiveLimit
		}
		for _, p := range parts {
			if p == ".." {
				return "", unsafeEntry(raw, "path traversal (..)")
			}
			if p == "" || p == "." {
				return "", unsafeEntry(raw, "path is not canonical (empty or . component)")
			}
		}
		if path.Clean(name) != name {
			return "", unsafeEntry(raw, "path is not canonical")
		}
		if typ, ok := seen[name]; ok && !(typ == 'i' && h.Typeflag == tar.TypeDir) {
			return "", unsafeEntry(raw, "duplicate or conflicting entry")
		}
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], "/")
			if typ := seen[parent]; typ == 'f' {
				return "", unsafeEntry(raw, "parent path is a file")
			}
			if seen[parent] == 0 {
				objects++
				if objects > cfg.MaxEntries {
					return "", errArchiveLimit
				}
				seen[parent] = 'i'
			}
		}
		if h.Size < 0 || h.Size > cfg.MaxExtractBytes-total {
			return "", errArchiveLimit
		}
		if seen[name] == 0 {
			objects++
			if objects > cfg.MaxEntries {
				return "", errArchiveLimit
			}
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		roots[parts[0]] = true
		if h.Typeflag == tar.TypeDir {
			if h.Size != 0 {
				return "", unsafeEntry(raw, "directory entry has data")
			}
			seen[name] = 'd'
			if err = os.MkdirAll(target, 0700); err != nil {
				return "", err
			}
			continue
		}
		// A file cannot replace an implicit parent directory.
		if seen[name] == 'i' {
			return "", unsafeEntry(raw, "file replaces a directory")
		}
		seen[name] = 'f'
		files++
		total += h.Size
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil {
			if errors.Is(copyErr, errArchiveLimit) || errors.Is(copyErr, context.Canceled) || errors.Is(copyErr, context.DeadlineExceeded) {
				return "", copyErr
			}
			return "", errors.Join(malformedArchive("truncated or corrupt file data"), copyErr)
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	if len(roots) == 0 {
		return "", malformedArchive("archive has no entries")
	}
	// Only zero tar padding may follow the terminal blocks. Reading to the real
	// EOF verifies gzip CRC/length and bounds expansion even after tar EOF.
	buf := make([]byte, 32768)
	for {
		n, err := bounded.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return "", malformedArchive("unexpected data after the tar end-of-archive marker")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if bounded.read%512 != 0 {
		return "", malformedArchive("tar stream is not a whole number of 512-byte blocks")
	}
	if gz != nil {
		if _, err := wire.ReadByte(); err != io.EOF {
			if errors.Is(err, errArchiveLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			return "", malformedArchive("unexpected data after the gzip stream")
		}
	}
	// A single top-level name is unwrapped once, as for ZIP: a wrapper
	// directory becomes the site, a lone file becomes a single-file release.
	if len(roots) == 1 {
		for name := range roots {
			return filepath.Join(dst, name), nil
		}
	}
	return dst, nil
}

func tarTypeReason(t byte) string {
	switch t {
	case tar.TypeSymlink:
		return "symbolic links are not allowed"
	case tar.TypeLink:
		return "hard links are not allowed"
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return "device and FIFO entries are not allowed"
	}
	return "only regular files and directories are allowed"
}

// originalEntries excludes publisher-private markers and only those compression
// siblings that were generated for an existing original. Standalone .gz/.br
// downloads are real originals and remain downloadable.
func originalEntries(root string) ([]string, error) {
	var names []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if p == root {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			return fmt.Errorf("invalid stored content")
		}
		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext == ".gz" || ext == ".br" {
				sibling, e := os.Lstat(strings.TrimSuffix(p, filepath.Ext(p)))
				if e == nil && sibling.Mode().IsRegular() {
					return nil
				}
				if e != nil && !errors.Is(e, fs.ErrNotExist) {
					return e
				}
			}
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		names = append(names, rel)
		return nil
	})
	return names, err
}
func writeOriginalArchive(ctx context.Context, w io.Writer, root, basename string) error {
	entries, err := originalEntries(root)
	if err != nil {
		return err
	}
	z := gzip.NewWriter(w)
	tw := tar.NewWriter(z)
	write := func() error {
		if err := tw.WriteHeader(&tar.Header{Name: basename + "/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			return err
		}
		for _, rel := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			p := filepath.Join(root, rel)
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			h, err := tar.FileInfoHeader(st, "")
			if err != nil {
				return err
			}
			h.Name = basename + "/" + filepath.ToSlash(rel)
			h.Uid = 0
			h.Gid = 0
			h.Uname = ""
			h.Gname = ""
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			if st.Mode().IsRegular() {
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				r := &archiveBudgetReader{r: f, left: st.Size(), ctx: ctx}
				_, err = io.CopyN(tw, r, st.Size())
				e := f.Close()
				if err != nil {
					return err
				}
				if e != nil {
					return e
				}
			}
		}
		return nil
	}
	err = write()
	return errors.Join(err, tw.Close(), z.Close())
}
