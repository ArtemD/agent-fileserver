package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type snapshotWriter struct {
	*httptest.ResponseRecorder
	beforeWrite func()
}

func (w *snapshotWriter) Write(b []byte) (int, error) {
	if w.beforeWrite != nil {
		fn := w.beforeWrite
		w.beforeWrite = nil
		fn()
	}
	return w.ResponseRecorder.Write(b)
}

func TestDownloadSnapshotSurvivesConcurrentMutation(t *testing.T) {
	for _, action := range []string{"delete", "update"} {
		t.Run(action, func(t *testing.T) {
			f := testAPI(t)
			v := publishAPI(t, f, `{}`, tarFixture{"a.txt", 0, "AAA", nil}, tarFixture{"b.txt", 0, "BBB", nil})
			w := &snapshotWriter{ResponseRecorder: httptest.NewRecorder(), beforeWrite: func() {
				if action == "delete" {
					if _, err := f.a.s.deleteRelease(v.Token); err != nil {
						t.Fatal(err)
					}
				} else {
					mcpView(t, f, "publish_files", fileArgs("new.txt", "replacement", map[string]any{"token": v.Token}))
				}
			}}
			// Mutation begins on the first response byte. It must not deadlock on the
			// store lock, and must not change the already prepared archive.
			f.a.download(w, httptest.NewRequest("GET", "/", nil), "test", v.manifest)
			if w.Code != 200 {
				t.Fatalf("download: %d %s", w.Code, w.Body.String())
			}
			gz, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			tr := tar.NewReader(gz)
			found := map[string]bool{}
			for {
				h, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				if h.Typeflag == tar.TypeReg {
					b, e := io.ReadAll(tr)
					if e != nil {
						t.Fatal(e)
					}
					found[string(b)] = true
				}
			}
			if len(found) != 2 || !found["AAA"] || !found["BBB"] {
				t.Fatalf("incomplete or mixed archive: %v", found)
			}
		})
	}
}

func TestDownloadSnapshotCancellationIsFailure(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{}`, tarFixture{"a.txt", 0, "AAA", nil}, tarFixture{"b.txt", 0, "BBB", nil})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	f.a.download(w, httptest.NewRequest("GET", "/", nil).WithContext(ctx), "test", v.manifest)
	if w.Code < 400 || w.Header().Get("Content-Type") == "application/gzip" {
		t.Fatalf("cancelled download succeeded: %d", w.Code)
	}
}

func TestDownloadSnapshotRechecksCurrentSize(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{}`, tarFixture{"a.txt", 0, "AAA", nil})
	m, err := f.a.s.info(v.Token)
	if err != nil {
		t.Fatal(err)
	}
	m.Bytes = mcpInlineBytes + 1
	if err = f.a.s.writeManifest(m); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.a.download(w, httptest.NewRequest("GET", "/", nil), "test", v.manifest)
	if w.Code != 413 {
		t.Fatalf("stale size accepted: %d", w.Code)
	}
}

// Fail after archive generation has begun, not before acquiring the lock.
type interruptedDownloadContext struct {
	context.Context
	checks int
}

func (c *interruptedDownloadContext) Err() error {
	c.checks++
	if c.checks >= 3 {
		return context.Canceled
	}
	return nil
}
func TestDownloadSnapshotArchiveFailureIsNotSuccess(t *testing.T) {
	f := testAPI(t)
	v := publishAPI(t, f, `{}`, tarFixture{"a.txt", 0, "AAA", nil}, tarFixture{"b.txt", 0, "BBB", nil})
	ctx := &interruptedDownloadContext{Context: context.Background()}
	w := httptest.NewRecorder()
	f.a.download(w, httptest.NewRequest("GET", "/", nil).WithContext(ctx), "test", v.manifest)
	if w.Code != 500 {
		t.Fatalf("archive generation failure returned success: %d", w.Code)
	}
	e := decodeErrorBody(t, w.Body.Bytes())
	if e.Error != "could not download release" || strings.Contains(w.Body.String(), f.a.s.root) {
		t.Fatalf("unsafe or unexpected error: %+v", e)
	}
}
