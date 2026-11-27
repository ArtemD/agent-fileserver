package main

// Human confirmation (MCP 2026-07-28 elicitation over multi round-trip
// requests) for the actions that cannot be undone or make a release public:
// delete_release, remove_password and an update in place. The model chooses
// tool arguments, so an argument cannot prove consent; the client asks the
// person in a form and retries the same call with their answer.
//
// Only clients that declare form elicitation on a 2026-07-28 request are
// asked. Everyone else keeps the earlier behaviour, so this protects people
// using an honest client (a model talked into an action by text it read),
// not against a malicious client, which authentication and account
// separation still handle.
//
// No state is stored: requestState is an expiry plus an HMAC, under a
// per-process random key, over the caller's account and key, the tool and the
// arguments that identify the action. A restart drops pending confirmations,
// which are then asked again.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	confirmInputID  = "confirm"
	confirmLifetime = 10 * time.Minute
	confirmLabelMax = 80
	// confirmMinProtocol is the first revision with multi round-trip requests.
	confirmMinProtocol = "2026-07-28"
)

type mcpCallKey struct{}

// confirmNote is added to the descriptions of the confirmed tools.
const confirmNote = " Clients that support it ask the user to confirm first; if the user declines, nothing changes: do not retry unless the user asks."

// confirmTarget names one action exactly; the requestState is bound to it.
type confirmTarget struct {
	Tool, Token, IdempotencyKey, SHA256 string
	Size                                int64
}

// clientCanConfirm reports whether this request's client said it can show a
// form: a 2026-07-28 request whose _meta client capabilities include
// elicitation (form, or no mode, which means form).
func clientCanConfirm(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	p := req.Session.InitializeParams()
	if p == nil || p.ProtocolVersion < confirmMinProtocol || p.Capabilities == nil || p.Capabilities.Elicitation == nil {
		return false
	}
	e := p.Capabilities.Elicitation
	return e.Form != nil || e.URL == nil
}

func (a *apiServer) confirmMAC(id agentIdentity, t confirmTarget, expiry int64) []byte {
	m := hmac.New(sha256.New, a.confirmSecret[:])
	for _, s := range []string{"agent-fileserver confirm v1", id.Account, id.ID, t.Tool, t.Token,
		t.IdempotencyKey, t.SHA256, strconv.FormatInt(t.Size, 10), strconv.FormatInt(expiry, 10)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		m.Write(n[:])
		m.Write([]byte(s))
	}
	return m.Sum(nil)
}

func (a *apiServer) confirmState(id agentIdentity, t confirmTarget, now time.Time) string {
	expiry := now.Add(confirmLifetime).Unix()
	b := binary.BigEndian.AppendUint64(nil, uint64(expiry))
	return base64.RawURLEncoding.EncodeToString(append(b, a.confirmMAC(id, t, expiry)...))
}

func (a *apiServer) confirmStateValid(id agentIdentity, t confirmTarget, state string, now time.Time) bool {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(b) != 8+sha256.Size {
		return false
	}
	expiry := int64(binary.BigEndian.Uint64(b[:8]))
	if now.Unix() > expiry || expiry > now.Add(confirmLifetime).Unix() {
		return false
	}
	return hmac.Equal(b[8:], a.confirmMAC(id, t, expiry))
}

// confirmLabel is the release label as one short line of plain text.
func confirmLabel(label string) string {
	label = strings.Join(strings.FieldsFunc(label, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}), " ")
	if r := []rune(label); len(r) > confirmLabelMax {
		label = string(r[:confirmLabelMax-1]) + "…"
	}
	return label
}

func confirmPrompt(tool string, v releaseView) (message, checkbox string) {
	name := "this release"
	if label := confirmLabel(v.Label); label != "" {
		name = fmt.Sprintf("the release %q", label)
	}
	switch tool {
	case "delete_release":
		return fmt.Sprintf("Delete %s permanently? The link %s stops working and the release cannot be restored.", name, v.URL),
			"Yes, delete it"
	case "remove_password":
		return fmt.Sprintf("Remove the visitor password from %s? Anyone with the link %s can then open it.", name, v.URL),
			"Yes, make it public"
	default:
		return fmt.Sprintf("Replace the content of %s with the new upload? The link %s stays the same and visitors see the new content at once.", name, v.URL),
			"Yes, replace the content"
	}
}

// mcpConfirm returns nil when the action may go ahead, or the result to
// return instead: a confirmation request, a refusal, or the lookup error.
func (a *apiServer) mcpConfirm(ctx context.Context, parent *http.Request, t confirmTarget) *mcp.CallToolResult {
	req, _ := ctx.Value(mcpCallKey{}).(*mcp.CallToolRequest)
	if !clientCanConfirm(req) || !validToken(t.Token) {
		return nil // earlier behaviour; an invalid token is refused by the action itself
	}
	identity, ok := ctx.Value(mcpIdentityKey{}).(agentIdentity)
	if !ok {
		return mcpFailure("missing authenticated request")
	}
	// Look the release up with the caller's account first: an unknown or
	// other account's release is refused exactly as before, with no prompt.
	w := a.mcpDispatch(ctx, parent, "GET", "/_api/v1/releases/"+t.Token, nil, "application/json", "", mcpOutputBytes)
	if w.overflow || w.status != http.StatusOK {
		return mcpAPIResult(w)
	}
	var v releaseView
	if json.Unmarshal(w.body.Bytes(), &v) != nil {
		return mcpFailure("could not prepare the confirmation")
	}
	now := time.Now()
	if answer, ok := req.Params.InputResponses[confirmInputID]; ok && a.confirmStateValid(identity, t, req.Params.RequestState, now) {
		if r, _ := answer.(*mcp.ElicitResult); r != nil && r.Action == "accept" && r.Content["confirm"] == true {
			return nil
		}
		return mcpFailure("cancelled: the user did not confirm")
	}
	// First call, or an answer without a valid state for this exact action
	// (expired, tampered, from another call or a restart): ask (again).
	message, checkbox := confirmPrompt(t.Tool, v)
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{confirmInputID: &mcp.ElicitParams{Mode: "form", Message: message,
			RequestedSchema: map[string]any{"type": "object", "required": []string{"confirm"},
				"properties": map[string]any{"confirm": map[string]any{"type": "boolean", "title": checkbox, "default": false}}}}},
		RequestState: a.confirmState(identity, t, now),
	}
}
