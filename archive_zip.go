package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func isZIPMagic(b []byte) bool {
	return len(b) >= 4 && (bytes.Equal(b[:4], []byte("PK\x03\x04")) ||
		bytes.Equal(b[:4], []byte("PK\x05\x06")) || bytes.Equal(b[:4], []byte("PK\x07\x08")))
}

var zipLE = binary.LittleEndian

type zipContextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r zipContextReaderAt) ReadAt(b []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(b, off)
}

// ZIP64, split disks, self-extracting prefixes and trailing bytes are not part
// of the upload format. Neither ZIP64 nor split disks is needed by our limits.
// Preflight the actual directory, not just its untrusted count: archive/zip
// otherwise allocates one File per record before we can enforce MaxEntries.
func zipDirectory(r io.ReaderAt, size int64, maxEntries int) (int64, []int64, error) {
	if size < 22 {
		return 0, nil, errUnsafeArchive
	}
	n := min(size, 22+65535)
	tail := make([]byte, int(n))
	if _, err := r.ReadAt(tail, size-n); err != nil {
		return 0, nil, err
	}
	e := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if string(tail[i:i+4]) == "PK\x05\x06" && i+22+int(zipLE.Uint16(tail[i+20:])) == len(tail) {
			e = i
			break
		}
	}
	if e < 0 {
		return 0, nil, errUnsafeArchive
	}
	end := tail[e:]
	count := int(zipLE.Uint16(end[10:]))
	if zipLE.Uint16(end[4:]) != 0 || zipLE.Uint16(end[6:]) != 0 ||
		int(zipLE.Uint16(end[8:])) != count || count == 65535 {
		return 0, nil, errUnsafeArchive
	}
	if count > maxEntries {
		return 0, nil, errArchiveLimit
	}
	start := int64(zipLE.Uint32(end[16:]))
	length := int64(zipLE.Uint32(end[12:]))
	stop := size - n + int64(e)
	if start+length != stop {
		return 0, nil, errUnsafeArchive
	}
	offsets := make([]int64, 0, count)
	for pos := start; pos < stop; {
		if len(offsets) >= maxEntries {
			return 0, nil, errArchiveLimit
		}
		var h [46]byte
		if stop-pos < int64(len(h)) {
			return 0, nil, errUnsafeArchive
		}
		if _, err := r.ReadAt(h[:], pos); err != nil {
			return 0, nil, err
		}
		if string(h[:4]) != "PK\x01\x02" || zipLE.Uint16(h[34:]) != 0 ||
			zipLE.Uint32(h[20:]) == ^uint32(0) || zipLE.Uint32(h[24:]) == ^uint32(0) ||
			zipLE.Uint32(h[42:]) == ^uint32(0) {
			return 0, nil, errUnsafeArchive
		}
		step := int64(46) + int64(zipLE.Uint16(h[28:])) + int64(zipLE.Uint16(h[30:])) + int64(zipLE.Uint16(h[32:]))
		if step > stop-pos {
			return 0, nil, errUnsafeArchive
		}
		offsets = append(offsets, int64(zipLE.Uint32(h[42:])))
		pos += step
	}
	if len(offsets) != count {
		return 0, nil, errUnsafeArchive
	}
	return start, offsets, nil
}

// Some Unix extensions can encode links independently of external mode bits.
// Do not interpret or silently turn such entries into regular published files.
func safeZIPExtra(extra []byte) bool {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return false
		}
		tag, n := zipLE.Uint16(extra), int(zipLE.Uint16(extra[2:]))
		if n > len(extra)-4 || tag == 0x0001 || tag == 0x000d || tag == 0x756e ||
			tag == 0x0017 || tag == 0x9901 {
			return false
		}
		extra = extra[4+n:]
	}
	return true
}

// Validate local records as well as the central directory. Go intentionally
// trusts the central metadata; uploads must not contain competing path/type
// interpretations, overlapping records, hidden local entries or truncated data.
func zipLocalEnd(r io.ReaderAt, f *zip.File, offset, directory int64) (int64, error) {
	var h [30]byte
	if offset < 0 || directory-offset < int64(len(h)) {
		return 0, errUnsafeArchive
	}
	if _, err := r.ReadAt(h[:], offset); err != nil {
		return 0, err
	}
	if string(h[:4]) != "PK\x03\x04" || zipLE.Uint16(h[6:]) != f.Flags || zipLE.Uint16(h[8:]) != f.Method {
		return 0, errUnsafeArchive
	}
	n, extra := int(zipLE.Uint16(h[26:])), int(zipLE.Uint16(h[28:]))
	data := offset + 30 + int64(n+extra)
	if data > directory || f.CompressedSize64 > uint64(directory-data) {
		return 0, errUnsafeArchive
	}
	b := make([]byte, n+extra)
	if _, err := r.ReadAt(b, offset+30); err != nil {
		return 0, err
	}
	if string(b[:n]) != f.Name || !safeZIPExtra(b[n:]) {
		return 0, errUnsafeArchive
	}
	end := data + int64(f.CompressedSize64)
	if f.Flags&8 == 0 {
		if zipLE.Uint32(h[14:]) != f.CRC32 || uint64(zipLE.Uint32(h[18:])) != f.CompressedSize64 ||
			uint64(zipLE.Uint32(h[22:])) != f.UncompressedSize64 {
			return 0, errUnsafeArchive
		}
	} else {
		// Streaming writers may leave zero or final values in local headers.
		for _, pair := range [][2]uint32{{zipLE.Uint32(h[14:]), f.CRC32}, {zipLE.Uint32(h[18:]), uint32(f.CompressedSize64)}, {zipLE.Uint32(h[22:]), uint32(f.UncompressedSize64)}} {
			if pair[0] != 0 && pair[0] != pair[1] {
				return 0, errUnsafeArchive
			}
		}
		var d [16]byte
		if directory-end < 12 {
			return 0, errUnsafeArchive
		}
		if _, err := r.ReadAt(d[:12], end); err != nil {
			return 0, err
		}
		descriptor := d[:12]
		if zipLE.Uint32(d[:]) == 0x08074b50 {
			if directory-end < 16 {
				return 0, errUnsafeArchive
			}
			if _, err := r.ReadAt(d[:], end); err != nil {
				return 0, err
			}
			descriptor = d[4:]
			end += 4
		}
		if zipLE.Uint32(descriptor) != f.CRC32 || uint64(zipLE.Uint32(descriptor[4:])) != f.CompressedSize64 ||
			uint64(zipLE.Uint32(descriptor[8:])) != f.UncompressedSize64 {
			return 0, errUnsafeArchive
		}
		end += 12
	}
	return end, nil
}

func zipPath(name string, dir bool) (string, []string, error) {
	if dir {
		name = strings.TrimSuffix(name, "/")
	}
	if !utf8.ValidString(name) || name == "" || len(name) > 1024 ||
		strings.ContainsAny(name, "\\:") || strings.HasPrefix(name, "/") {
		return "", nil, errUnsafeArchive
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return "", nil, errArchiveLimit
	}
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", nil, errUnsafeArchive
		}
		if p == "Icon\r" && i == len(parts)-1 && !dir {
			continue // the one explicitly recognized Mac control-character name
		}
		for _, c := range p {
			if unicode.IsControl(c) {
				return "", nil, errUnsafeArchive
			}
		}
	}
	return name, parts, nil
}

func zipMacLeaf(name string) bool {
	return name == ".DS_Store" || name == "Icon\r" || (strings.HasPrefix(name, "._") && len(name) > 2)
}

func copyZIPEntry(ctx context.Context, out io.Writer, r io.ReaderAt, f *zip.File) error {
	offset, err := f.DataOffset()
	if err != nil {
		return err
	}
	compressed := io.NewSectionReader(r, offset, int64(f.CompressedSize64))
	// Give flate a ByteReader so its stream-end detection does not hide
	// unconsumed bytes in an internal read-ahead buffer. This rejects junk or
	// unlisted local records disguised as part of a compressed extent.
	buffer := bufio.NewReader(compressed)
	var src io.Reader = buffer
	var decoder io.ReadCloser
	if f.Method == zip.Deflate {
		decoder = flate.NewReader(buffer)
		src = decoder
	}
	hash := crc32.NewIEEE()
	bounded := &archiveBudgetReader{r: src, left: int64(f.UncompressedSize64), ctx: ctx}
	n, copyErr := io.CopyN(io.MultiWriter(out, hash), bounded, int64(f.UncompressedSize64))
	if copyErr == nil {
		// Probe EOF without ever writing a bomb's look-ahead byte to disk.
		var probe [1]byte
		extra, endErr := io.ReadFull(bounded, probe[:])
		if extra != 0 {
			copyErr = errArchiveLimit
		} else if endErr != io.EOF {
			copyErr = endErr
		}
	}
	var closeErr error
	if decoder != nil {
		closeErr = decoder.Close()
	}
	position, seekErr := compressed.Seek(0, io.SeekCurrent)
	if copyErr == nil && (uint64(n) != f.UncompressedSize64 || hash.Sum32() != f.CRC32 ||
		position-int64(buffer.Buffered()) != int64(f.CompressedSize64)) {
		copyErr = errUnsafeArchive
	}
	return errors.Join(copyErr, closeErr, seekErr)
}

func extractZIP(ctx context.Context, input io.ReaderAt, size int64, dst string, cfg apiConfig) (string, error) {
	r := zipContextReaderAt{ctx, input}
	directory, offsets, err := zipDirectory(r, size, cfg.MaxEntries)
	if err != nil {
		return "", errors.Join(errUnsafeArchive, err)
	}
	z, err := zip.NewReader(r, size)
	if err != nil || len(z.File) != len(offsets) {
		return "", errors.Join(errUnsafeArchive, err)
	}
	type entry struct {
		file      *zip.File
		name      string
		dir, omit bool
	}
	entries := make([]entry, 0, len(z.File))
	seen := map[string]byte{}
	roots := map[string]bool{}
	files := 0
	var total uint64
	ranges := make([][2]int64, 0, len(z.File))
	// Validate every entry, including omitted metadata, before writing anything.
	for i, f := range z.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		switch f.CreatorVersion >> 8 {
		case 3, 19: // Unix, macOS: reject unknown Unix inode types too.
			typ := (f.ExternalAttrs >> 16) & 0170000
			if typ != 0 && typ != 0100000 && typ != 0040000 {
				return "", errUnsafeArchive
			}
		case 0, 10, 14: // FAT, NTFS, VFAT: devices/reparse points are not files.
			if f.ExternalAttrs&0x440 != 0 {
				return "", errUnsafeArchive
			}
		default:
			return "", errUnsafeArchive
		}
		mode := f.Mode()
		dir := mode.IsDir()
		if (mode.Type() != 0 && mode.Type() != os.ModeDir) || dir != strings.HasSuffix(f.Name, "/") ||
			f.Flags & ^uint16(0x080e) != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) ||
			!safeZIPExtra(f.Extra) {
			return "", errUnsafeArchive
		}
		// Bits 1/2 are deflate options, not legal for stored data.
		if f.Method == zip.Store && (f.Flags&6 != 0 || f.CompressedSize64 != f.UncompressedSize64) {
			return "", errUnsafeArchive
		}
		name, parts, err := zipPath(f.Name, dir)
		if err != nil {
			return "", err
		}
		if typ, exists := seen[name]; exists && !(typ == 'i' && dir) {
			return "", errUnsafeArchive
		}
		for j := 1; j < len(parts); j++ {
			p := strings.Join(parts[:j], "/")
			if seen[p] == 'f' {
				return "", errUnsafeArchive
			}
			if seen[p] == 0 {
				seen[p] = 'i'
			}
		}
		seen[name] = 'f'
		if dir {
			seen[name] = 'd'
		}
		if len(seen) > cfg.MaxEntries {
			return "", errArchiveLimit
		}
		if f.UncompressedSize64 > uint64(cfg.MaxExtractBytes)-total {
			return "", errArchiveLimit
		}
		total += f.UncompressedSize64
		if dir && f.UncompressedSize64 != 0 {
			return "", errUnsafeArchive
		}
		end, err := zipLocalEnd(r, f, offsets[i], directory)
		if err != nil {
			return "", errors.Join(errUnsafeArchive, err)
		}
		ranges = append(ranges, [2]int64{offsets[i], end})
		macTree := parts[0] == "__MACOSX"
		omit := (!dir && zipMacLeaf(parts[len(parts)-1])) || (macTree && dir)
		if macTree && !dir && !omit {
			return "", errUnsafeArchive
		}
		if !omit {
			roots[parts[0]] = true
			if !dir {
				files++
			}
		}
		entries = append(entries, entry{f, name, dir, omit})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	var end int64
	for _, span := range ranges {
		if span[0] != end {
			return "", errUnsafeArchive
		}
		end = span[1]
	}
	if end != directory || files == 0 {
		// Empty, metadata-only and directory-only ZIPs do not publish anything.
		return "", errUnsafeArchive
	}
	if err := noSymlinkAncestors(dst, false); err != nil {
		return "", err
	}
	existing, err := os.ReadDir(dst)
	if err != nil || len(existing) != 0 {
		return "", errors.Join(errUnsafeArchive, err)
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var out io.Writer = io.Discard
		var target *os.File
		if !e.omit {
			if e.dir {
				err = root.MkdirAll(e.name, 0700)
			} else {
				err = root.MkdirAll(filepath.Dir(e.name), 0700)
				if err == nil {
					target, err = root.OpenFile(e.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					out = target
				}
			}
			if err != nil {
				return "", err
			}
		}
		// Validate directory and omitted metadata payloads too, including CRC=0.
		copyErr := copyZIPEntry(ctx, out, r, e.file)
		var closeErr error
		if target != nil {
			closeErr = target.Close()
		}
		if err := errors.Join(copyErr, closeErr); err != nil {
			return "", errors.Join(errUnsafeArchive, err)
		}
	}
	if len(roots) == 1 {
		for name := range roots {
			return filepath.Join(dst, name), nil
		}
	}
	return dst, nil
}
