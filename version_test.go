package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAndVersionDoNotOpenStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("FSERVER_ROOT", root)
	t.Setenv("FSERVER_BASE_URL", "")
	for _, arg := range []string{"--help", "-h", "help", "version", "--version"} {
		var out, errOut bytes.Buffer
		if err := run([]string{arg}, &out, &errOut); err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if out.Len() == 0 || errOut.Len() != 0 {
			t.Fatalf("%s: unexpected output", arg)
		}
		if strings.Contains(arg, "version") && !strings.Contains(out.String(), buildVersion) {
			t.Fatal("missing build version")
		}
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("help/version touched filesystem state")
	}
}

func TestDefaultTokenFileUsesConfiguredRoot(t *testing.T) {
	t.Setenv("FSERVER_TOKEN_FILE", "")
	root := t.TempDir()
	t.Setenv("FSERVER_ROOT", root)
	if got := defaultTokenFile(); got != filepath.Join(root, "credentials", "tokens.json") {
		t.Fatal("token default ignored configured root")
	}
	t.Setenv("FSERVER_ROOT", "")
	if got := defaultTokenFile(); got != "/var/lib/agent-fileserver/credentials/tokens.json" {
		t.Fatal("unexpected installed token default")
	}
}
