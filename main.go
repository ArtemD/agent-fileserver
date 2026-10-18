package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

var buildVersion = "dev"

const usage = "usage: publish [--json] [--spa] [--label TEXT] SOURCE\n       publish list [--json]\n       publish info TOKEN [--json]\n       publish unpublish TOKEN [--json]\n       publish token create --label NAME [--days N]\n       publish token list | revoke LABEL\n       publish migrate-policies\n       publish serve --socket PATH [--token-file PATH]\n       publish version | --help"

type arguments struct {
	command, operand, label string
	json, spa               bool
}

func parseArgs(args []string) (arguments, error) {
	a := arguments{command: "publish"}
	if len(args) > 0 && (args[0] == "list" || args[0] == "info" || args[0] == "unpublish") {
		a.command = args[0]
		args = args[1:]
	}
	positional := []string{}
	flags := true
	for i := 0; i < len(args); i++ {
		s := args[i]
		switch {
		case flags && s == "--":
			flags = false
		case flags && s == "--json":
			a.json = true
		case flags && s == "--spa" && a.command == "publish":
			a.spa = true
		case flags && s == "--label" && a.command == "publish":
			i++
			if i == len(args) {
				return a, fmt.Errorf("--label requires text")
			}
			a.label = args[i]
		case flags && strings.HasPrefix(s, "--label=") && a.command == "publish":
			a.label = strings.TrimPrefix(s, "--label=")
		case flags && strings.HasPrefix(s, "-") &&
			!((a.command == "info" || a.command == "unpublish") && validToken(s)):
			return a, fmt.Errorf("unknown option %q", s)
		default:
			positional = append(positional, s)
		}
	}
	want := 1
	if a.command == "list" {
		want = 0
	}
	if len(positional) != want {
		return a, fmt.Errorf("%s", usage)
	}
	if want == 1 {
		a.operand = positional[0]
	}
	return a, nil
}

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
		case "token", "migrate-policies", "serve":
			return runManagement(args, stdout, stderr)
		}
	}
	a, err := parseArgs(args)
	if err != nil {
		return err
	}
	s, err := newStore(os.Getenv("FSERVER_ROOT"), os.Getenv("FSERVER_BASE_URL"))
	if err != nil {
		return err
	}
	var result any
	switch a.command {
	case "publish":
		m, warning, e := s.publish(a.operand, a.label, a.spa)
		if e != nil {
			return e
		}
		result = m
		if warning != "" {
			fmt.Fprintln(stderr, "publish: warning:", warning)
		}
	case "list":
		result, err = s.list()
		a.json = true
	case "info":
		result, err = s.info(a.operand)
	case "unpublish":
		result, err = s.unpublish(a.operand)
	}
	if err != nil {
		return err
	}
	if a.json {
		return json.NewEncoder(stdout).Encode(result)
	}
	_, err = fmt.Fprintln(stdout, result.(manifest).URL)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
}
