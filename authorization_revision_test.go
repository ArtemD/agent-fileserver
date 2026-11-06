package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Runs the real repository routes with a gate after successful authorization.
// CI supplies the binary extracted from the same pinned image as deployment.
func TestCaddyAuthorizationRevision(t *testing.T) {
	binary := os.Getenv("FSERVER_TEST_CADDY_BIN")
	if binary == "" {
		t.Skip("set FSERVER_TEST_CADDY_BIN to the pinned Caddy binary")
	}
	for _, revised := range []bool{false, true} {
		name := "legacy"
		if revised {
			name = "revision"
		}
		t.Run(name, func(t *testing.T) {
			f := testAPI(t)
			v, _ := mcpView(t, f, "publish_files", fileArgs("index.html", "OLD_PUBLIC", nil))
			if revised {
				mcpView(t, f, "publish_files", fileArgs("index.html", "OLD_PUBLIC", map[string]any{"token": v.Token}))
			}
			authorized, resume := make(chan struct{}), make(chan struct{})
			var pause, release sync.Once
			var omitRoot atomic.Bool
			gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec := httptest.NewRecorder()
				f.a.ServeHTTP(rec, r)
				if omitRoot.Load() {
					rec.Header().Del("X-Fserver-Content-Root")
				}
				if rec.Code == 204 {
					pause.Do(func() { close(authorized); <-resume })
				}
				for k, vs := range rec.Header() {
					for _, val := range vs {
						w.Header().Add(k, val)
					}
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
			}))
			defer gate.Close()
			defer release.Do(func() { close(resume) })
			routes, err := os.ReadFile("deploy/caddy/routes.caddy")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			cfg := strings.ReplaceAll(string(routes), "/srv/public", f.a.s.public)
			cfg = strings.ReplaceAll(cfg, "unix//run/agent-fileserver-api/http.sock", strings.TrimPrefix(gate.URL, "http://"))
			cfg = strings.ReplaceAll(cfg, "/var/log/agent-fileserver/access.json", filepath.Join(dir, "access.json"))
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()
			cf := filepath.Join(dir, "Caddyfile")
			if err = os.WriteFile(cf, []byte("{\n admin off\n auto_https off\n}\nhttp://"+addr+" {\n"+cfg+"\n}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cmd := exec.Command(binary, "run", "--config", cf, "--adapter", "caddyfile")
			cmd.Stderr = &logs
			cmd.Stdout = &logs
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			}()
			client := &http.Client{Timeout: 10 * time.Second}
			base := "http://" + addr
			ready := false
			for i := 0; i < 250; i++ {
				r, e := client.Get(base + "/robots.txt")
				if e == nil {
					_ = r.Body.Close()
					ready = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("Caddy did not start")
			}
			type result struct {
				status int
				body   string
				err    error
			}
			get := func(password string) result {
				r, _ := http.NewRequest("GET", base+"/"+v.Token+"/index.html", nil)
				// Caller input must never choose the content root or cache policy.
				r.Header.Set("X-Fserver-Content-Root", ".")
				r.Header.Set("X-Fserver-Cache-Control", "public, no-cache")
				if password != "" {
					r.SetBasicAuth("viewer", password)
				}
				res, e := client.Do(r)
				if e != nil {
					return result{err: e}
				}
				defer res.Body.Close()
				b, e := io.ReadAll(res.Body)
				return result{res.StatusCode, string(b), e}
			}
			finished := make(chan result, 1)
			go func() { finished <- get("") }()
			select {
			case <-authorized:
			case <-time.After(5 * time.Second):
				t.Fatal("authorization gate not reached")
			}
			mcpView(t, f, "publish_files", fileArgs("index.html", "NEW_PRIVATE", map[string]any{"token": v.Token, "password": "test-password"}))
			release.Do(func() { close(resume) })
			got := <-finished
			if got.err != nil || (got.status != 404 && !(got.status == 200 && got.body == "OLD_PUBLIC")) {
				t.Fatalf("stale authorization served a replacement: %+v", got)
			}
			if fresh := get(""); fresh.err != nil || fresh.status != 401 {
				t.Fatalf("anonymous replacement: %+v", fresh)
			}
			if fresh := get("test-password"); fresh.err != nil || fresh.status != 200 || fresh.body != "NEW_PRIVATE" {
				t.Fatalf("authenticated replacement: %+v", fresh)
			}
			omitRoot.Store(true)
			if fresh := get("test-password"); fresh.err != nil || fresh.status != 404 {
				t.Fatalf("missing trusted content root did not fail closed: %+v", fresh)
			}
		})
	}
}
