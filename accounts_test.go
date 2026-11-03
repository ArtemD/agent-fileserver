package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accountKey returns a fixture whose key belongs to account (issue #32).
func accountKey(t *testing.T, f apiFixture, label, account string) apiFixture {
	t.Helper()
	_, key, err := f.tokens.Create(label, account, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	return f
}

func pageArgs(text string, extra map[string]any) map[string]any {
	args := map[string]any{"idempotency_key": requestID(),
		"files": []map[string]any{{"path": "index.html", "text": "<!doctype html><title>t</title>" + text}}}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

func listTokens(t *testing.T, f apiFixture) (tokens []string, count int, total int64) {
	t.Helper()
	var out struct {
		Releases []map[string]any `json:"releases"`
		Count    int              `json:"count"`
		Total    int64            `json:"total_bytes"`
	}
	raw := mcpTool(t, f, "list_releases", map[string]any{}, false)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Releases {
		if _, ok := r["owner"]; ok {
			t.Fatalf("list_releases shows the owner field: %s", raw)
		}
		tokens = append(tokens, r["token"].(string))
	}
	return tokens, out.Count, out.Total
}

func toolError(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Error
}

func TestAccountsSeeAndManageOnlyTheirOwnReleases(t *testing.T) {
	owner := testAPI(t) // the fixture key is in the default account
	maria := accountKey(t, owner, "maria laptop", "maria")
	mariaPhone := accountKey(t, owner, "maria phone", "maria")

	mine := mcpPublishFile(t, owner, pageArgs("owner page", nil))
	hers := mcpPublishFile(t, maria, pageArgs("maria page", nil))
	before := mcpTool(t, owner, "release_info", map[string]any{"token": mine.Token}, false)

	got, count, total := listTokens(t, owner)
	if len(got) != 1 || got[0] != mine.Token || count != 1 || total != mine.Bytes {
		t.Fatalf("owner list: %v count=%d total=%d", got, count, total)
	}
	got, count, _ = listTokens(t, maria)
	if len(got) != 1 || got[0] != hers.Token || count != 1 {
		t.Fatalf("maria list: %v count=%d", got, count)
	}
	// Keys of one account share its releases.
	if got, _, _ = listTokens(t, mariaPhone); len(got) != 1 || got[0] != hers.Token {
		t.Fatalf("second key of the account: %v", got)
	}
	mcpTool(t, mariaPhone, "set_expiry", map[string]any{"token": hers.Token, "expires_in_days": 3}, false)

	var info map[string]any
	_ = json.Unmarshal(mcpTool(t, maria, "server_info", map[string]any{}, false), &info)
	if info["account"] != "maria" || info["agent"] != "maria laptop" {
		t.Fatalf("server_info: %v", info)
	}
	_ = json.Unmarshal(mcpTool(t, owner, "server_info", map[string]any{}, false), &info)
	if info["account"] != defaultAccount {
		t.Fatalf("server_info of a pre-account key: %v", info)
	}

	// Every tool that names a release answers another account's token exactly
	// like an unknown one.
	unknown := "AAAAAAAAAAAAAAAAAAAAAA"
	calls := []struct {
		name string
		args func(token string) map[string]any
	}{
		{"release_info", func(tk string) map[string]any { return map[string]any{"token": tk} }},
		{"download_release", func(tk string) map[string]any { return map[string]any{"token": tk} }},
		{"delete_release", func(tk string) map[string]any { return map[string]any{"token": tk} }},
		{"set_password", func(tk string) map[string]any {
			return map[string]any{"token": tk, "password": "correct horse battery"}
		}},
		{"reset_password", func(tk string) map[string]any { return map[string]any{"token": tk} }},
		{"remove_password", func(tk string) map[string]any { return map[string]any{"token": tk} }},
		{"set_expiry", func(tk string) map[string]any { return map[string]any{"token": tk, "expires_in_days": 1} }},
		{"publish_files", func(tk string) map[string]any { return pageArgs("taken over", map[string]any{"token": tk}) }},
		{"upload_from_computer", func(tk string) map[string]any { return map[string]any{"token": tk} }},
	}
	for _, c := range calls {
		other := toolError(t, mcpTool(t, maria, c.name, c.args(mine.Token), true))
		missing := toolError(t, mcpTool(t, maria, c.name, c.args(unknown), true))
		if other != "release not found" || other != missing {
			t.Fatalf("%s on another account's release: %q (unknown token: %q)", c.name, other, missing)
		}
	}
	data := []byte("<!doctype html><title>x</title>ticket takeover")
	body := beginFails(t, maria, beginArgs(data, map[string]any{"filename": "index.html", "token": mine.Token}))
	if !strings.Contains(body, "release not found") {
		t.Fatalf("begin_upload on another account's release: %.300s", body)
	}

	after := mcpTool(t, owner, "release_info", map[string]any{"token": mine.Token}, false)
	if string(after) != string(before) {
		t.Fatalf("another account changed the release:\nbefore %s\nafter  %s", before, after)
	}
	if strings.Contains(string(after), "owner") {
		t.Fatalf("release view shows the owner: %s", after)
	}
	// And the owner cannot touch maria's release either.
	if e := toolError(t, mcpTool(t, owner, "delete_release", map[string]any{"token": hers.Token}, true)); e != "release not found" {
		t.Fatalf("owner deleted another account's release: %q", e)
	}
	mcpTool(t, mariaPhone, "delete_release", map[string]any{"token": hers.Token}, false)
	mcpTool(t, owner, "delete_release", map[string]any{"token": mine.Token}, false)
}

func TestAccountsUploadTicketPublishesIntoItsAccount(t *testing.T) {
	owner := testAPI(t)
	maria := accountKey(t, owner, "maria", "maria")
	data := []byte("<!doctype html><title>t</title>uploaded")
	v := releaseOf(t, putTicket(maria, beginUpload(t, maria, beginArgs(data, map[string]any{"filename": "index.html"})), data))
	if got, _, _ := listTokens(t, owner); len(got) != 0 {
		t.Fatalf("maria's upload is listed for owner: %v", got)
	}
	if got, _, _ := listTokens(t, maria); len(got) != 1 || got[0] != v.Token {
		t.Fatalf("maria's upload is not hers: %v", got)
	}
	// An update ticket of the owning account still works.
	next := []byte("<!doctype html><title>t</title>updated")
	u := releaseOf(t, putTicket(maria, beginUpload(t, maria, beginArgs(next, map[string]any{"filename": "index.html", "token": v.Token})), next))
	if u.Token != v.Token || u.UpdatedAt == nil {
		t.Fatalf("ticket update: %+v", u)
	}
}

func TestAccountsManifestOwnerAndLegacyReleases(t *testing.T) {
	owner := testAPI(t)
	maria := accountKey(t, owner, "maria", "maria")
	mine := mcpPublishFile(t, owner, pageArgs("owner", nil))
	hers := mcpPublishFile(t, maria, pageArgs("maria", nil))
	read := func(token string) string {
		b, err := os.ReadFile(filepath.Join(owner.a.s.manifests, token+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// Default-account manifests keep their pre-account form; others name the owner.
	if strings.Contains(read(mine.Token), `"owner"`) || !strings.Contains(read(hers.Token), `"owner":"maria"`) {
		t.Fatalf("manifests: %s / %s", read(mine.Token), read(hers.Token))
	}
	// A release published before accounts existed (no owner) is the default account's.
	m, err := owner.a.s.info(mine.Token)
	if err != nil || m.Owner != "" || m.account() != defaultAccount {
		t.Fatalf("legacy release: %+v %v", m, err)
	}
}

func TestStoreReplaceRefusesAnotherAccount(t *testing.T) {
	s := testStore(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "index.html"), []byte("<p>maria</p>"), 0644); err != nil {
		t.Fatal(err)
	}
	policy, _ := makeAccessPolicy("")
	m, _, err := s.publishRelease(context.Background(), src, releaseOptions{Label: "maria", Policy: &policy, Owner: "maria"})
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"", defaultAccount, "mallory"} {
		if _, _, err = s.publishRelease(context.Background(), src, releaseOptions{Replace: m.Token, Owner: owner}); err != errNotOwner {
			t.Fatalf("owner %q replaced maria's release: %v", owner, err)
		}
	}
	if _, _, err = s.publishRelease(context.Background(), src, releaseOptions{Replace: m.Token, Owner: "maria"}); err != nil {
		t.Fatal(err)
	}
}

func TestTokenRegistryAccounts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tokens.json")
	store, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "Maria", "-maria", ".maria", "ma ria", "maria/x", "märia", strings.Repeat("a", 65)} {
		if _, _, err = store.Create("bad-"+bad, bad, 0); err == nil {
			t.Fatalf("accepted account %q", bad)
		}
	}
	for _, good := range []string{"maria", "a", "team-1.design_x", strings.Repeat("a", 64)} {
		if !validAccount(good) {
			t.Fatalf("refused account %q", good)
		}
	}
	summary, raw, err := store.Create("maria", "maria", 0)
	if err != nil || summary.Account != "maria" {
		t.Fatal(summary, err)
	}
	if id, err := store.Authenticate(raw, time.Now()); err != nil || id.Account != "maria" {
		t.Fatal(id, err)
	}
	_, ownerRaw, err := store.Create("owner laptop", defaultAccount, 0)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := store.Authenticate(ownerRaw, time.Now()); err != nil || id.Account != defaultAccount {
		t.Fatal(id, err)
	}
	b, _ := os.ReadFile(path)
	var reg struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err = json.Unmarshal(b, &reg); err != nil || len(reg.Tokens) != 2 {
		t.Fatal(string(b), err)
	}
	// The default account is stored as no field, the pre-account form.
	if reg.Tokens[0]["account"] != "maria" || reg.Tokens[1]["account"] != nil {
		t.Fatalf("stored accounts: %s", b)
	}
	rows, err := store.List()
	if err != nil || len(rows) != 2 || rows[0].Account != "maria" || rows[1].Account != defaultAccount {
		t.Fatalf("list: %+v %v", rows, err)
	}
	// Spelling the default account out, or an invalid name, is not a valid registry.
	for _, account := range []string{defaultAccount, "Bad"} {
		edited := strings.Replace(string(b), `"account":"maria"`, `"account":"`+account+`"`, 1)
		if err = os.WriteFile(path, []byte(edited), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Authenticate(raw, time.Now()); err == nil {
			t.Fatalf("registry with account %q accepted", account)
		}
	}
}
