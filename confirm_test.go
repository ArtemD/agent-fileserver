package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type confirmReply struct {
	Code          int
	Raw           string
	ResultType    string
	IsError       bool
	Text          string
	InputRequests map[string]json.RawMessage
	RequestState  string
}

// confirmCall sends one sessionless 2026-07-28 tools/call. With elicit the
// client declares form elicitation; answer and state are the retry's
// inputResponses["confirm"] and requestState.
func confirmCall(t *testing.T, f apiFixture, tool string, args map[string]any, elicit bool, answer map[string]any, state string) confirmReply {
	t.Helper()
	caps := map[string]any{}
	if elicit {
		caps["elicitation"] = map[string]any{"form": map[string]any{}}
	}
	params := map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientCapabilities": caps,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "confirm-test", "version": "1"}}}
	if answer != nil {
		params["inputResponses"] = map[string]any{confirmInputID: answer}
	}
	if state != "" {
		params["requestState"] = state
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(b))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2026-07-28")
	r.Header.Set("Mcp-Method", "tools/call")
	r.Header.Set("Mcp-Name", tool)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	var out struct {
		Result struct {
			ResultType string `json:"resultType"`
			IsError    bool   `json:"isError"`
			Content    []struct {
				Text string `json:"text"`
			} `json:"content"`
			InputRequests map[string]json.RawMessage `json:"inputRequests"`
			RequestState  string                     `json:"requestState"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %d %s (%v)", tool, w.Code, w.Body, err)
	}
	reply := confirmReply{Code: w.Code, Raw: w.Body.String(), ResultType: out.Result.ResultType, IsError: out.Result.IsError,
		InputRequests: out.Result.InputRequests, RequestState: out.Result.RequestState}
	if len(out.Result.Content) > 0 {
		reply.Text = out.Result.Content[0].Text
	}
	return reply
}

// asked checks that the reply is a confirmation request naming the release.
func asked(t *testing.T, r confirmReply, v releaseView, wantText string) {
	t.Helper()
	req := string(r.InputRequests[confirmInputID])
	if r.Code != 200 || r.ResultType != "input_required" || r.IsError || r.Text != "" || r.RequestState == "" ||
		!strings.Contains(req, "elicitation/create") || !strings.Contains(req, `"mode":"form"`) ||
		!strings.Contains(req, v.URL) || !strings.Contains(req, wantText) || !strings.Contains(req, `"required":["confirm"]`) {
		t.Fatalf("not a confirmation request: %s", r.Raw)
	}
}

func accepted(confirm any) map[string]any {
	return map[string]any{"action": "accept", "content": map[string]any{"confirm": confirm}}
}

func copyConfirmArgs(args map[string]any) map[string]any {
	copy := make(map[string]any, len(args))
	for key, value := range args {
		copy[key] = value
	}
	return copy
}

func releaseExists(t *testing.T, f apiFixture, token string) bool {
	t.Helper()
	w := mcpPost(t, f, "tools/call", map[string]any{"name": "release_info", "arguments": map[string]any{"token": token}})
	return w.Code == 200 && strings.Contains(w.Body.String(), `\"token\":\"`+token+`\"`)
}

func TestConfirmDeleteRelease(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, pageArgs("keep", map[string]any{"label": "Quarterly\u202e   report"}))
	args := map[string]any{"token": v.Token}

	first := confirmCall(t, f, "delete_release", args, true, nil, "")
	asked(t, first, v, `the release \"Quarterly report\"`)
	if !strings.Contains(first.Raw, "cannot be restored") || !releaseExists(t, f, v.Token) {
		t.Fatalf("delete prompt or early delete: %s", first.Raw)
	}
	// Refusals change nothing and explain themselves.
	for _, answer := range []map[string]any{{"action": "decline"}, {"action": "cancel"}, accepted(false), accepted("true"), {"action": "accept"}} {
		r := confirmCall(t, f, "delete_release", args, true, answer, first.RequestState)
		if !r.IsError || !strings.Contains(r.Text, `"error":"cancelled: the user did not confirm"`) || !strings.Contains(r.Text, `"hint":"The user declined`) || !releaseExists(t, f, v.Token) {
			t.Fatalf("answer %v: %s", answer, r.Raw)
		}
	}
	// An acceptance without a valid state for this exact action asks again.
	other := mcpPublishFile(t, f, pageArgs("other", nil))
	otherState := confirmCall(t, f, "delete_release", map[string]any{"token": other.Token}, true, nil, "").RequestState
	removeState := confirmCall(t, f, "remove_password", args, true, nil, "").RequestState
	tampered := []byte(first.RequestState)
	tampered[len(tampered)/2] ^= 1
	for _, state := range []string{"", "not-base64!", string(tampered), otherState, removeState} {
		r := confirmCall(t, f, "delete_release", args, true, accepted(true), state)
		asked(t, r, v, "Delete")
		if !releaseExists(t, f, v.Token) {
			t.Fatalf("state %q deleted the release", state)
		}
	}
	// Another key of the same account may not reuse the state either.
	sameAccount := f
	_, sameAccount.key, _ = f.tokens.Create("second key", defaultAccount, 0)
	if r := confirmCall(t, sameAccount, "delete_release", args, true, accepted(true), first.RequestState); r.ResultType != "input_required" || !releaseExists(t, f, v.Token) {
		t.Fatalf("state reused by another key: %s", r.Raw)
	}

	done := confirmCall(t, f, "delete_release", args, true, accepted(true), first.RequestState)
	if done.ResultType != "complete" || done.IsError || !strings.Contains(done.Text, `"ok":true`) || releaseExists(t, f, v.Token) {
		t.Fatalf("confirmed delete: %s", done.Raw)
	}
}

func TestConfirmRemovePasswordAndUpdates(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, pageArgs("secret", map[string]any{"password": "correct horse battery"}))
	args := map[string]any{"token": v.Token}
	r := confirmCall(t, f, "remove_password", args, true, nil, "")
	asked(t, r, v, "Anyone with the link")
	if !strings.Contains(r.Raw, `the release \"index.html\"`) && !strings.Contains(r.Raw, "this release") {
		t.Fatalf("remove_password prompt names no release: %s", r.Raw)
	}
	if !strings.Contains(string(mcpTool(t, f, "release_info", args, false)), `"protected":true`) {
		t.Fatal("password removed before confirmation")
	}
	if done := confirmCall(t, f, "remove_password", args, true, accepted(true), r.RequestState); done.IsError ||
		!strings.Contains(string(mcpTool(t, f, "release_info", args, false)), `"protected":false`) {
		t.Fatalf("confirmed remove_password: %s", done.Raw)
	}

	// Update in place with publish_files: the live content stays until confirmed.
	update := pageArgs("new content", map[string]any{"token": v.Token})
	r = confirmCall(t, f, "publish_files", update, true, nil, "")
	asked(t, r, v, "Replace the content")
	// The state is bound to the idempotency key: other bytes need a new answer.
	changed := pageArgs("other content", map[string]any{"token": v.Token})
	if again := confirmCall(t, f, "publish_files", changed, true, accepted(true), r.RequestState); again.ResultType != "input_required" {
		t.Fatalf("state accepted for another update: %s", again.Raw)
	}
	if done := confirmCall(t, f, "publish_files", update, true, accepted(true), r.RequestState); done.IsError || done.ResultType != "complete" ||
		!strings.Contains(done.Text, `"token":"`+v.Token+`"`) {
		t.Fatalf("confirmed update: %s", done.Raw)
	}
	// A new release (no token) is never asked about.
	if r = confirmCall(t, f, "publish_files", pageArgs("fresh", nil), true, nil, ""); r.ResultType != "complete" || r.IsError {
		t.Fatalf("new release asked for confirmation: %s", r.Raw)
	}

	// begin_upload with token: no ticket before confirmation.
	ticket := map[string]any{"size": 5, "sha256": strings.Repeat("a", 64), "filename": "index.html", "idempotency_key": requestID(), "token": v.Token}
	r = confirmCall(t, f, "begin_upload", ticket, true, nil, "")
	asked(t, r, v, "Replace the content")
	if strings.Contains(r.Raw, "Authorization") {
		t.Fatalf("ticket minted before confirmation: %s", r.Raw)
	}
	bigger := map[string]any{}
	for k, val := range ticket {
		bigger[k] = val
	}
	bigger["size"] = 6
	if again := confirmCall(t, f, "begin_upload", bigger, true, accepted(true), r.RequestState); again.ResultType != "input_required" {
		t.Fatalf("state accepted for another upload: %s", again.Raw)
	}
	if done := confirmCall(t, f, "begin_upload", ticket, true, accepted(true), r.RequestState); done.IsError || !strings.Contains(done.Text, "Authorization") {
		t.Fatalf("confirmed begin_upload: %s", done.Raw)
	}
	// set_password and reset_password are not confirmed.
	if r = confirmCall(t, f, "reset_password", args, true, nil, ""); r.ResultType != "complete" || r.IsError {
		t.Fatalf("reset_password asked: %s", r.Raw)
	}
}

func TestConfirmBindsEveryUpdateField(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, pageArgs("original", nil))

	inline := pageArgs("inline", map[string]any{"token": v.Token})
	inlineState := confirmCall(t, f, "publish_files", inline, true, nil, "")
	asked(t, inlineState, v, "Replace the content")
	for name, value := range map[string]any{
		"files":           []map[string]any{{"path": "index.html", "text": "changed"}},
		"label":           "changed label",
		"spa":             true,
		"password":        "new-password",
		"expires_in_days": 7,
	} {
		t.Run("inline "+name, func(t *testing.T) {
			changed := copyConfirmArgs(inline)
			changed[name] = value
			asked(t, confirmCall(t, f, "publish_files", changed, true, accepted(true), inlineState.RequestState), v, "Replace the content")
		})
	}

	archive := base64.StdEncoding.EncodeToString(fixtureZIP(t, zipFile("index.html", "archive")))
	archiveArgs := map[string]any{"archive_base64": archive, "idempotency_key": requestID(), "token": v.Token}
	archiveState := confirmCall(t, f, "publish_archive", archiveArgs, true, nil, "")
	asked(t, archiveState, v, "Replace the content")
	for name, value := range map[string]any{
		"archive_base64":  base64.StdEncoding.EncodeToString(fixtureZIP(t, zipFile("index.html", "changed archive"))),
		"label":           "changed label",
		"spa":             true,
		"password":        "new-password",
		"expires_in_days": 7,
	} {
		t.Run("archive "+name, func(t *testing.T) {
			changed := copyConfirmArgs(archiveArgs)
			changed[name] = value
			asked(t, confirmCall(t, f, "publish_archive", changed, true, accepted(true), archiveState.RequestState), v, "Replace the content")
		})
	}

	ticket := map[string]any{"size": 5, "sha256": strings.Repeat("a", 64), "idempotency_key": requestID(), "token": v.Token}
	ticketState := confirmCall(t, f, "begin_upload", ticket, true, nil, "")
	asked(t, ticketState, v, "Replace the content")
	for name, value := range map[string]any{
		"size":            6,
		"sha256":          strings.Repeat("b", 64),
		"filename":        "index.html",
		"label":           "changed label",
		"spa":             true,
		"password":        "new-password",
		"expires_in_days": 7,
	} {
		t.Run("ticket "+name, func(t *testing.T) {
			changed := copyConfirmArgs(ticket)
			changed[name] = value
			asked(t, confirmCall(t, f, "begin_upload", changed, true, accepted(true), ticketState.RequestState), v, "Replace the content")
		})
	}
}

func TestConfirmRequiresFreshStateAfterReleaseChanges(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, pageArgs("original", map[string]any{"password": "original-password"}))
	update := pageArgs("confirmed", map[string]any{"token": v.Token})
	state := confirmCall(t, f, "publish_files", update, true, nil, "")
	asked(t, state, v, "Replace the content")

	// This is the same account acting through a client without elicitation.
	// It simulates a normal concurrent update, not an unauthenticated change.
	mcpPublishFile(t, f, pageArgs("concurrent content", map[string]any{"token": v.Token}))
	asked(t, confirmCall(t, f, "publish_files", update, true, accepted(true), state.RequestState), v, "Replace the content")

	remove := confirmCall(t, f, "remove_password", map[string]any{"token": v.Token}, true, nil, "")
	asked(t, remove, v, "Anyone with the link")
	mcpTool(t, f, "set_password", map[string]any{"token": v.Token, "password": "replaced-password"}, false)
	asked(t, confirmCall(t, f, "remove_password", map[string]any{"token": v.Token}, true, accepted(true), remove.RequestState), v, "Anyone with the link")
}

func TestConfirmTicketRefusesChangedRelease(t *testing.T) {
	f := testAPI(t)
	v := mcpPublishFile(t, f, pageArgs("original", map[string]any{"password": "old-password"}))
	data := []byte("hello")
	ticketArgs := beginArgs(data, map[string]any{"filename": "index.html", "token": v.Token})
	confirmation := confirmCall(t, f, "begin_upload", ticketArgs, true, nil, "")
	asked(t, confirmation, v, "Replace the content")
	done := confirmCall(t, f, "begin_upload", ticketArgs, true, accepted(true), confirmation.RequestState)
	if done.IsError {
		t.Fatalf("confirmed ticket: %s", done.Raw)
	}
	var ticket uploadTicketView
	if err := json.Unmarshal([]byte(done.Text), &ticket); err != nil || ticket.Headers["Authorization"] == "" {
		t.Fatalf("ticket %s: %v", done.Raw, err)
	}

	mcpPublishFile(t, f, pageArgs("concurrent content", map[string]any{"token": v.Token}))
	w := putTicket(f, ticket, data)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"error":"release changed since confirmation"`) ||
		!strings.Contains(w.Body.String(), `"hint":`) {
		t.Fatalf("stale ticket: %d %s", w.Code, w.Body)
	}
	// The stale ticket did not weaken the old policy or replace its current bytes.
	authorize := httptest.NewRequest("GET", "/_internal/authorize", nil)
	authorize.Header.Set("X-Forwarded-Uri", "/"+v.Token+"/index.html")
	authorize.Header.Set("X-Fserver-Client-IP", "192.0.2.1")
	authorize.SetBasicAuth("viewer", "old-password")
	authorized := httptest.NewRecorder()
	f.a.ServeHTTP(authorized, authorize)
	if authorized.Code != http.StatusNoContent || authorized.Header().Get("X-Fserver-Cache-Control") != "private, no-store" {
		t.Fatalf("old policy after stale ticket: %d %s", authorized.Code, authorized.Header())
	}
	var current struct {
		ContentBase64 string `json:"content_base64"`
	}
	if raw := mcpTool(t, f, "download_release", map[string]any{"token": v.Token}, false); json.Unmarshal(raw, &current) != nil {
		t.Fatalf("current release: %s", raw)
	} else if bytes, err := base64.StdEncoding.DecodeString(current.ContentBase64); err != nil || !strings.Contains(string(bytes), "concurrent content") {
		t.Fatalf("old content after stale ticket: %q (%v)", bytes, err)
	}

	fresh := confirmCall(t, f, "begin_upload", ticketArgs, true, nil, "")
	asked(t, fresh, v, "Replace the content")
	done = confirmCall(t, f, "begin_upload", ticketArgs, true, accepted(true), fresh.RequestState)
	if done.IsError {
		t.Fatalf("fresh confirmed ticket: %s", done.Raw)
	}
	if err := json.Unmarshal([]byte(done.Text), &ticket); err != nil || ticket.Headers["Authorization"] == "" {
		t.Fatalf("fresh ticket %s: %v", done.Raw, err)
	}
	if retried := putTicket(f, ticket, data); retried.Code != http.StatusCreated {
		t.Fatalf("same key after fresh approval: %d %s", retried.Code, retried.Body)
	}
}

func TestConfirmDeleteSurvivesUnreadablePolicy(t *testing.T) {
	broken := []byte(`{"protected":`)
	for name, change := range map[string]struct{ before, after []byte }{
		"missing to malformed":      {nil, broken},
		"malformed to missing":      {broken, nil},
		"malformed contents change": {broken, []byte(`{"updated_at":`)},
	} {
		t.Run(name, func(t *testing.T) {
			f := testAPI(t)
			v := mcpPublishFile(t, f, pageArgs("keep", nil))
			path := filepath.Join(f.a.s.policies, v.Token+".json")
			writePolicy := func(data []byte) {
				t.Helper()
				var err error
				if data == nil {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, data, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			args := map[string]any{"token": v.Token}
			writePolicy(change.before)
			confirmation := confirmCall(t, f, "delete_release", args, true, nil, "")
			asked(t, confirmation, v, "Delete")
			writePolicy(change.after)
			fresh := confirmCall(t, f, "delete_release", args, true, accepted(true), confirmation.RequestState)
			asked(t, fresh, v, "Delete")
			done := confirmCall(t, f, "delete_release", args, true, accepted(true), fresh.RequestState)
			if _, err := f.a.s.info(v.Token); done.IsError || err == nil {
				t.Fatalf("delete with %s policy: %s", name, done.Raw)
			}
		})
	}
}

func TestConfirmOnlyWhenTheClientCanAsk(t *testing.T) {
	f := testAPI(t)
	// No elicitation capability: the earlier behaviour, at once.
	v := mcpPublishFile(t, f, pageArgs("a", nil))
	if r := confirmCall(t, f, "delete_release", map[string]any{"token": v.Token}, false, nil, ""); r.ResultType != "complete" || r.IsError || releaseExists(t, f, v.Token) {
		t.Fatalf("delete without elicitation: %s", r.Raw)
	}
	// 2025-06-18 clients never get an input request.
	v = mcpPublishFile(t, f, pageArgs("b", nil))
	if raw := mcpTool(t, f, "delete_release", map[string]any{"token": v.Token}, false); !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("2025-06-18 delete: %s", raw)
	}
	// Unknown tokens and other accounts' releases: release not found, no prompt.
	v = mcpPublishFile(t, f, pageArgs("c", nil))
	other := accountKey(t, f, "other", "other-account")
	for _, c := range []struct {
		f     apiFixture
		token string
	}{{f, "AAAAAAAAAAAAAAAAAAAAAA"}, {other, v.Token}} {
		for _, tool := range []string{"delete_release", "remove_password"} {
			r := confirmCall(t, c.f, tool, map[string]any{"token": c.token}, true, nil, "")
			if !r.IsError || r.InputRequests != nil || !strings.Contains(r.Text, `"error":"release not found"`) || strings.Contains(r.Raw, v.URL) {
				t.Fatalf("%s on a foreign or unknown release: %s", tool, r.Raw)
			}
		}
		if r := confirmCall(t, c.f, "publish_files", pageArgs("x", map[string]any{"token": c.token}), true, nil, ""); r.InputRequests != nil || !strings.Contains(r.Text, "release not found") {
			t.Fatalf("update of a foreign or unknown release: %s", r.Raw)
		}
	}
	if !releaseExists(t, f, v.Token) {
		t.Fatal("another account changed the release")
	}
}

func TestConfirmStateExpiresAndLabels(t *testing.T) {
	a := &apiServer{}
	id := agentIdentity{ID: "k1", Account: defaultAccount}
	target := confirmTarget{Tool: "delete_release", Token: "AAAAAAAAAAAAAAAAAAAAAA"}
	now := time.Now()
	state := a.confirmState(id, target, now)
	if !a.confirmStateValid(id, target, state, now.Add(confirmLifetime-time.Second)) ||
		a.confirmStateValid(id, target, state, now.Add(confirmLifetime+2*time.Second)) ||
		a.confirmStateValid(agentIdentity{ID: "k1", Account: "other"}, target, state, now) {
		t.Fatal("state lifetime or binding")
	}
	// A state claiming a later expiry than any this server issues is refused.
	far := a.confirmState(id, target, now.Add(time.Hour))
	if a.confirmStateValid(id, target, far, now) {
		t.Fatal("state from the future accepted")
	}
	b := &apiServer{}
	b.confirmSecret[0] = 1
	if b.confirmStateValid(id, target, state, now) {
		t.Fatal("state accepted under another key (after a restart)")
	}
	long := strings.Repeat("x", 200)
	if got := confirmLabel("  a\tb​\x00c " + long); len([]rune(got)) != confirmLabelMax || !strings.HasPrefix(got, "a b c x") || !strings.HasSuffix(got, "…") {
		t.Fatalf("label %q", got)
	}
}

// The official SDK client with an elicitation handler completes the
// confirmation by itself: the person's answer decides.
func TestConfirmOfficialSDKClient(t *testing.T) {
	f := testAPI(t)
	server := httptest.NewServer(f.a)
	defer server.Close()
	clientHTTP := &http.Client{Transport: mcpTestTransport(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+f.key)
		return http.DefaultTransport.RoundTrip(r)
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, accept := range []bool{false, true} {
		v := mcpPublishFile(t, f, pageArgs("sdk", nil))
		var asked []string
		client := mcp.NewClient(&mcp.Implementation{Name: "SDK confirm", Version: "test"}, &mcp.ClientOptions{
			ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				asked = append(asked, req.Params.Message)
				if !accept {
					return &mcp.ElicitResult{Action: "decline"}, nil
				}
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true}}, nil
			}})
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: clientHTTP, MaxRetries: -1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "delete_release", Arguments: map[string]any{"token": v.Token}})
		session.Close()
		if err != nil {
			t.Fatal(err)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if len(asked) != 1 || !strings.Contains(asked[0], v.URL) || res.IsError == accept || releaseExists(t, f, v.Token) != !accept ||
			!accept && !strings.Contains(text, "cancelled: the user did not confirm") {
			t.Fatalf("accept=%v asked=%q isError=%v text=%s", accept, asked, res.IsError, text)
		}
	}
}
