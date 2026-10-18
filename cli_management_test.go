package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagementTokenCLI(t *testing.T) {
	dir := t.TempDir()
	registry := filepath.Join(dir, "credentials", "tokens.json")
	t.Setenv("FSERVER_TOKEN_FILE", registry)
	var out, diagnostics bytes.Buffer
	for _, args := range [][]string{
		{"token"}, {"token", "unknown"}, {"token", "create"},
		{"token", "create", "--label", "test", "--days", "-1"},
		{"token", "list", "unexpected"}, {"token", "revoke"},
		{"serve"}, {"migrate-policies", "unexpected"},
	} {
		if err := run(args, &out, &diagnostics); err == nil {
			t.Fatalf("accepted invalid args %q", args)
		}
	}
	if _, err := os.Lstat(registry); !os.IsNotExist(err) {
		t.Fatal("invalid command created registry")
	}
	out.Reset()
	if err := run([]string{"token", "create", "--label", "fixture", "--days", "1"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(out.String())
	if len(raw) < 43 || strings.ContainsAny(raw, " \n\r\t") {
		t.Fatal("create did not print just one raw credential")
	}
	out.Reset()
	if err := run([]string{"token", "list"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list: %s %v", out.String(), err)
	}
	if strings.Contains(out.String(), raw) || strings.Contains(out.String(), "hash") {
		t.Fatal("list leaked credential/hash")
	}
	if err := run([]string{"token", "revoke", "fixture"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	store, err := newTokenStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Authenticate(raw, time.Now()); err == nil {
		t.Fatal("revoked token authenticated")
	}
}

func TestManagementPolicyMigrationCLI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	t.Setenv("FSERVER_ROOT", root)
	t.Setenv("FSERVER_BASE_URL", "https://example.invalid")
	s, err := newStore(root, "https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "fixture.txt")
	if err = os.WriteFile(source, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	m, _, err := s.publish(source, "legacy fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(s.public, m.Token), 0755) })
	policyFile := filepath.Join(root, "policies", m.Token+".json")
	if err = os.Remove(policyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = s.policy(m.Token); err == nil {
		t.Fatal("missing legacy policy did not fail closed")
	}
	var stdout, stderr bytes.Buffer
	if err = run([]string{"migrate-policies"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	policy, err := s.policy(m.Token)
	if err != nil || policy.Protected {
		t.Fatalf("migration did not create public policy: %v", err)
	}
	before, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"migrate-policies"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(policyFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("migration rewrote an existing policy")
	}
	if stdout.Len() != 0 {
		t.Fatal("migration unexpectedly printed private metadata")
	}
}

func TestManagementSocketSafety(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.sock")
	l, cleanup, err := listenManagementSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0660 {
		t.Fatalf("socket permissions: %v %v", st, err)
	}
	if _, _, err = listenManagementSocket(path); err == nil {
		t.Fatal("replaced existing socket")
	}
	l.Close()
	cleanup()
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("own socket not cleaned")
	}
	if err = os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = listenManagementSocket(path); err == nil {
		t.Fatal("replaced existing file")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dir, "target"), path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = listenManagementSocket(path); err == nil {
		t.Fatal("followed socket symlink")
	}
}

func TestManagementCleanupDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	_, cleanup, err := listenManagementSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatal("cleanup deleted a replacement path")
	}
}

func TestManagementServerDeadlinesAndShutdown(t *testing.T) {
	server := managementHTTPServer(http.NotFoundHandler())
	if server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 180*time.Second ||
		server.WriteTimeout != 180*time.Second || server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 32<<10 {
		t.Fatal("HTTP hardening changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "api.sock")
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		done <- serveManagement(ctx, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			w.WriteHeader(204)
		}))
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		for {
			c, err := d.DialContext(ctx, "unix", path)
			if err == nil {
				return c, nil
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("http://unix/_internal/health")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("server left socket")
	}
}

func TestManagementShutdownWaitsForInflightRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "api.sock")
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- serveManagement(ctx, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-release
			w.WriteHeader(204)
		}))
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		for {
			c, err := d.DialContext(ctx, "unix", path)
			if err == nil {
				return c, nil
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}}
	defer transport.CloseIdleConnections()
	clientDone := make(chan error, 1)
	go func() {
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("http://unix/test")
		if err == nil {
			response.Body.Close()
		}
		clientDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("shutdown returned before in-flight request: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}
