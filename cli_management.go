package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func defaultTokenFile() string {
	if p := os.Getenv("FSERVER_TOKEN_FILE"); p != "" {
		return p
	}
	root := os.Getenv("FSERVER_ROOT")
	if root == "" {
		root = "/var/lib/agent-fileserver"
	}
	return filepath.Join(root, "credentials", "tokens.json")
}

func managementFlags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	return f
}

func runManagement(args []string, stdout, stderr io.Writer) error {
	switch args[0] {
	case "token":
		if len(args) < 2 {
			return fmt.Errorf("usage: publish token create|list|revoke")
		}
		// Parse before opening the registry; typos must not create credentials.
		label, days := "", 0
		switch args[1] {
		case "create":
			f := managementFlags("token create", stderr)
			f.StringVar(&label, "label", "", "unique agent label")
			f.IntVar(&days, "days", 0, "validity in days (0: no expiry)")
			if err := f.Parse(args[2:]); err != nil {
				return err
			}
			if f.NArg() != 0 || label == "" || days < 0 {
				return fmt.Errorf("usage: publish token create --label NAME [--days N]")
			}
		case "list":
			if len(args) != 2 {
				return fmt.Errorf("usage: publish token list")
			}
		case "revoke":
			if len(args) != 3 || args[2] == "" {
				return fmt.Errorf("usage: publish token revoke LABEL")
			}
			label = args[2]
		default:
			return fmt.Errorf("unknown token command")
		}
		t, err := newTokenStore(defaultTokenFile())
		if err != nil {
			return err
		}
		switch args[1] {
		case "create":
			_, raw, err := t.Create(label, days)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(stdout, raw)
			return err
		case "list":
			rows, err := t.List()
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(rows)
		default:
			return t.Revoke(label)
		}
	case "migrate-policies":
		if len(args) != 1 {
			return fmt.Errorf("usage: publish migrate-policies")
		}
		s, err := newStore(os.Getenv("FSERVER_ROOT"), os.Getenv("FSERVER_BASE_URL"))
		if err != nil {
			return err
		}
		return s.migratePolicies()
	case "serve":
		f := managementFlags("serve", stderr)
		socket := f.String("socket", "", "required Unix socket path")
		tokenFile := f.String("token-file", defaultTokenFile(), "private token registry")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *socket == "" {
			return fmt.Errorf("usage: publish serve --socket PATH [--token-file PATH]")
		}
		s, err := newStore(os.Getenv("FSERVER_ROOT"), os.Getenv("FSERVER_BASE_URL"))
		if err != nil {
			return err
		}
		t, err := newTokenStore(*tokenFile)
		if err != nil {
			return err
		}
		handler, err := newAPIServer(s, t, apiConfig{Namespace: os.Getenv("FSERVER_NAMESPACE")})
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return serveManagement(ctx, *socket, handler)
	}
	return fmt.Errorf("unknown management command")
}

// Refuse existing paths, including stale sockets: never unlink another service.
// systemd RuntimeDirectory supplies an owner-writable, otherwise read-only parent.
func listenManagementSocket(path string) (*net.UnixListener, func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	if err = noSymlinkAncestors(abs, true); err != nil {
		return nil, nil, err
	}
	parent, err := os.Stat(filepath.Dir(abs))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return nil, nil, fmt.Errorf("socket parent must exist and not be group/world writable")
	}
	if _, err = os.Lstat(abs); !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("socket path must not already exist")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: abs, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	l.SetUnlinkOnClose(false)
	created, err := os.Lstat(abs)
	if err != nil {
		l.Close()
		return nil, nil, err
	}
	cleanup := func() {
		l.Close()
		if current, e := os.Lstat(abs); e == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(created, current) {
			_ = os.Remove(abs)
		}
	}
	if err = os.Chmod(abs, 0660); err != nil {
		cleanup()
		return nil, nil, err
	}
	return l, cleanup, nil
}

func managementHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 180 * time.Second, WriteTimeout: 180 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
	}
}

func serveManagement(ctx context.Context, socket string, handler http.Handler) error {
	l, cleanup, err := listenManagementSocket(socket)
	if err != nil {
		return err
	}
	defer cleanup()
	server := managementHTTPServer(handler)
	done := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if server.Shutdown(shutdownCtx) != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	err = server.Serve(l)
	close(done)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
