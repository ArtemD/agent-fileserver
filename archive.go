package main

import (
	"archive/tar"
	"bufio"
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

// extractArtifact accepts single-root tar/tar.gz and flat or single-wrapper ZIP.
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

// Tar keeps its original exactly-one-root and directory-only semantics.
func extractTar(ctx context.Context, wire *bufio.Reader, dst string, cfg apiConfig) (string, error) {
	var stream io.Reader = wire
	var gz *gzip.Reader
	magic, _ := wire.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		var err error
		gz, err = gzip.NewReader(wire)
		if err != nil {
			return "", errUnsafeArchive
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
	root := ""
	count := 0
	objects := 0
	var total int64
	for {
		before := bounded.read
		h, err := tr.Next()
		if err == io.EOF {
			// archive/tar tolerates a missing end marker; our wire contract does not.
			if bounded.read-before < 1024 {
				return "", errUnsafeArchive
			}
			break
		}
		if err != nil {
			if errors.Is(err, errArchiveLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			return "", errUnsafeArchive
		}
		count++
		if count > cfg.MaxEntries {
			return "", errArchiveLimit
		}
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return "", errUnsafeArchive
		}
		for key := range h.PAXRecords {
			if strings.Contains(strings.ToLower(key), "sparse") || key == "SCHILY.realsize" {
				return "", errUnsafeArchive
			}
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !utf8.ValidString(name) || len(name) == 0 || len(name) > 1024 || strings.ContainsAny(name, "\\\x00\r\n") || strings.HasPrefix(name, "/") {
			return "", errUnsafeArchive
		}
		parts := strings.Split(name, "/")
		if len(parts) > 32 {
			return "", errArchiveLimit
		}
		for _, p := range parts {
			if p == "" || p == "." || p == ".." {
				return "", errUnsafeArchive
			}
		}
		if path.Clean(name) != name {
			return "", errUnsafeArchive
		}
		if root == "" {
			root = parts[0]
		}
		if root != parts[0] {
			return "", errUnsafeArchive
		}
		if typ, ok := seen[name]; ok && !(typ == 'i' && h.Typeflag == tar.TypeDir) {
			return "", errUnsafeArchive
		}
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], "/")
			if typ := seen[parent]; typ == 'f' {
				return "", errUnsafeArchive
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
		if h.Typeflag == tar.TypeDir {
			if h.Size != 0 {
				return "", errUnsafeArchive
			}
			seen[name] = 'd'
			if err = os.MkdirAll(target, 0700); err != nil {
				return "", err
			}
			continue
		}
		// A file cannot replace an implicit parent directory.
		if seen[name] == 'i' {
			return "", errUnsafeArchive
		}
		seen[name] = 'f'
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
			return "", errors.Join(errUnsafeArchive, copyErr)
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	if root == "" {
		return "", errUnsafeArchive
	}
	// Only zero tar padding may follow the terminal blocks. Reading to the real
	// EOF verifies gzip CRC/length and bounds expansion even after tar EOF.
	buf := make([]byte, 32768)
	for {
		n, err := bounded.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return "", errUnsafeArchive
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
		return "", errUnsafeArchive
	}
	if gz != nil {
		if _, err := wire.ReadByte(); err != io.EOF {
			if errors.Is(err, errArchiveLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			return "", errUnsafeArchive
		}
	}
	return filepath.Join(dst, root), nil
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
