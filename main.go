package main

import (
	"fmt"
	"io"
	"os"
)

var buildVersion = "dev"

// MCP is the only management interface. This binary serves it and offers
// owner-only local key administration; it never publishes from the CLI.
const usage = "usage: agent-fileserver token create --label NAME [--days N]\n       agent-fileserver token list | revoke LABEL\n       agent-fileserver migrate-policies\n       agent-fileserver serve --socket PATH [--token-file PATH]\n       agent-fileserver healthcheck --socket PATH\n       agent-fileserver version | --help"

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h", "help":
			_, err := fmt.Fprintln(stdout, usage)
			return err
		case "version", "--version":
			_, err := fmt.Fprintln(stdout, "agent-fileserver "+buildVersion)
			return err
		}
	}
	if len(args) > 0 {
		switch args[0] {
		case "token", "migrate-policies", "serve", "healthcheck":
			return runManagement(args, stdout, stderr)
		}
	}
	return fmt.Errorf("%s", usage)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agent-fileserver:", err)
		os.Exit(1)
	}
}
