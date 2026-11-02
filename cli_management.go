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
	"strconv"
	"syscall"
	"time"
)

// envPositive reads an optional positive integer limit; unset or empty means
// the built-in default (0). Anything else that is not a positive integer fails.
func envPositive(name string) (int64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer number of bytes or entries", name)
	}
	return n, nil
}

// defaultExpiryDays is the release expiry when FSERVER_DEFAULT_EXPIRY_DAYS is unset.
const defaultExpiryDays = 60

// envExpiryDays reads the default release expiry: unset is 60 days, 0 means
// new releases never expire by default.
func envExpiryDays(name string) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultExpiryDays, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxExpiryDays {
		return 0, fmt.Errorf("%s must be a whole number of days from 0 (never expire) to %d", name, maxExpiryDays)
	}
	return n, nil
}

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
			return fmt.Errorf("usage: agent-fileserver token create|list|revoke")
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
				return fmt.Errorf("usage: agent-fileserver token create --label NAME [--days N]")
			}
		case "list":
			if len(args) != 2 {
				return fmt.Errorf("usage: agent-fileserver token list")
			}
		case "revoke":
			if len(args) != 3 || args[2] == "" {
				return fmt.Errorf("usage: agent-fileserver token revoke LABEL")
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
			return fmt.Errorf("usage: agent-fileserver migrate-policies")
		}
		s, err := newStore(os.Getenv("FSERVER_ROOT"), os.Getenv("FSERVER_BASE_URL"))
		if err != nil {
			return err
		}
		return s.migratePolicies()
	case "healthcheck":
		f := managementFlags("healthcheck", stderr)
		socket := f.String("socket", "", "required Unix socket path")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *socket == "" {
			return fmt.Errorf("usage: agent-fileserver healthcheck --socket PATH")
		}
		return healthcheck(*socket)
	case "serve":
		f := managementFlags("serve", stderr)
		socket := f.String("socket", "", "required Unix socket path")
		tokenFile := f.String("token-file", defaultTokenFile(), "private token registry")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *socket == "" {
			return fmt.Errorf("usage: agent-fileserver serve --socket PATH [--token-file PATH]")
		}
		s, err := newStore(os.Getenv("FSERVER_ROOT"), os.Getenv("FSERVER_BASE_URL"))
		if err != nil {
			return err
		}
		t, err := newTokenStore(*tokenFile)
		if err != nil {
			return err
		}
		cfg := apiConfig{Namespace: os.Getenv("FSERVER_NAMESPACE")}
		if cfg.MaxUploadBytes, err = envPositive("FSERVER_MAX_UPLOAD_BYTES"); err != nil {
			return err
		}
		if cfg.MaxExtractBytes, err = envPositive("FSERVER_MAX_EXTRACT_BYTES"); err != nil {
			return err
		}
		entries, err := envPositive("FSERVER_MAX_ENTRIES")
		if err != nil {
			return err
		}
		if entries > 1000000 {
			return fmt.Errorf("FSERVER_MAX_ENTRIES must be at most 1000000")
		}
		cfg.MaxEntries = int(entries)
		if cfg.DefaultExpiryDays, err = envExpiryDays("FSERVER_DEFAULT_EXPIRY_DAYS"); err != nil {
			return err
		}
		handler, err := newAPIServer(s, t, cfg)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		go handler.runExpirySweeper(ctx, expirySweepInterval)
		return serveManagement(ctx, *socket, handler)
	}
	return fmt.Errorf("unknown management command")
}

// removeStaleSocket deletes a leftover socket from a crashed previous run, so a
// restarted container recovers. It refuses anything that is not a socket owned
// by this UID, and any socket that still accepts connections (a live service).
func removeStaleSocket(abs string) error {
	st, err := os.Lstat(abs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if st.Mode()&os.ModeSocket == 0 || !ok || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("socket path exists and is not a stale socket owned by this user")
	}
	if c, err := net.DialTimeout("unix", abs, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("socket path is in use by a running service")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("socket path exists and its state is unknown: %w", err)
	}
	return os.Remove(abs)
}

// The socket parent must be owner-writable only (a private runtime directory).
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
	if err = removeStaleSocket(abs); err != nil {
		return nil, nil, err
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

// healthcheck asks the running service over its private socket; used by the
// container HEALTHCHECK so the runtime image needs no curl.
func healthcheck(socket string) error {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}
	resp, err := client.Get("http://localhost/_internal/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
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
