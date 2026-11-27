package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
