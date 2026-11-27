package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestMCPPublishSkill(t *testing.T) {
	f := testAPI(t)
	modern := func(method, name string, params map[string]any) *httptest.ResponseRecorder {
		return mcpPost20260728(t, f, method, name, params, true)
	}
	w := modern("server/discover", "", nil)
	var discover struct {
		Result struct {
			Capabilities struct {
				Extensions map[string]map[string]any `json:"extensions"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &discover); err != nil || w.Code != 200 {
		t.Fatalf("discover: %d %s (%v)", w.Code, w.Body, err)
	}
	extensions := discover.Result.Capabilities.Extensions
	if extensions[skillsExtensionID] == nil || len(extensions[skillsExtensionID]) != 0 || extensions[uiExtensionID] == nil {
		t.Fatalf("wrong discover extensions: %+v", extensions)
	}

	readResult := func(w *httptest.ResponseRecorder) skillResult {
		t.Helper()
		var envelope struct {
			Result skillResult     `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &envelope)
		r := envelope.Result
		if err != nil || w.Code != 200 || len(envelope.Error) != 0 || r.ResultType != "complete" ||
			r.CacheScope != "private" || !strings.Contains(w.Body.String(), `"ttlMs":0`) || w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatalf("skill reply: %d %s (%v)", w.Code, w.Body, err)
		}
		return r
	}
	listed := readResult(modern("skills/list", "", nil))
	got := readResult(modern("skills/get", "", map[string]any{"uri": publishSkillURI}))
	if len(listed.Skills) != 1 || got.Skill == nil || !reflect.DeepEqual(listed.Skills[0], *got.Skill) {
		t.Fatalf("list and get disagree: %+v %+v", listed, got)
	}
	entry := got.Skill
	if entry.URI != publishSkillURI || entry.Frontmatter["name"] != publishSkillName ||
		len(entry.Frontmatter) != 2 || len(entry.Resources) != 1 {
		t.Fatalf("invalid entry: %+v", entry)
	}

	w = modern("resources/read", publishSkillURI, map[string]any{"uri": publishSkillURI})
	var resource struct {
		Result struct {
			Contents []struct {
				URI      string `json:"uri"`
				MIMEType string `json:"mimeType"`
				Text     string `json:"text"`
			} `json:"contents"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resource); err != nil || w.Code != 200 || len(resource.Result.Contents) != 1 {
		t.Fatalf("resources/read: %d %s (%v)", w.Code, w.Body, err)
	}
	content := resource.Result.Contents[0]
	if content.URI != publishSkillURI || content.MIMEType != "text/markdown" || content.Text != publishSkillMarkdown ||
		entry.Resources[0] != (skillFile{
			URI: content.URI, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content.Text))), Size: len(content.Text),
		}) {
		t.Fatal("manifest does not match the Markdown resource")
	}
	description, err := json.Marshal(entry.Frontmatter["description"])
	if err != nil || !strings.HasPrefix(content.Text, "---\nname: publish-release\ndescription: "+string(description)+"\n---\n") {
		t.Fatal("manifest frontmatter does not match the Markdown resource")
	}
}

func TestMCPSkillFallbackAndRefusals(t *testing.T) {
	f := testAPI(t)
	legacy := mcpPost(t, f, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "legacy", "version": "1"},
	})
	if legacy.Code != 200 || strings.Contains(legacy.Body.String(), skillsExtensionID) {
		t.Fatalf("legacy initialize: %d %s", legacy.Code, legacy.Body)
	}
	refused := func(w *httptest.ResponseRecorder, code int64, message string) {
		t.Helper()
		var envelope struct {
			Error struct {
				Code    int64        `json:"code"`
				Message string       `json:"message"`
				Data    apiErrorBody `json:"data"`
			} `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &envelope)
		if err != nil || envelope.Error.Code != code || envelope.Error.Message != message ||
			envelope.Error.Data.Hint == "" || len(envelope.Result) != 0 {
			t.Fatalf("wrong refusal: %d %s (%v)", w.Code, w.Body, err)
		}
	}
	if w := mcpPost(t, f, "skills/list", map[string]any{}); !strings.Contains(w.Body.String(), `"code":-32601`) {
		t.Fatalf("legacy skill call should be unavailable: %d %s", w.Code, w.Body)
	}
	refused(mcpPost20260728(t, f, "skills/get", "", map[string]any{"uri": "skill://other/SKILL.md"}, true),
		jsonrpc.CodeInvalidParams, "skill not found")
	refused(mcpPost20260728(t, f, "skills/list", "", map[string]any{"cursor": "unknown"}, true),
		jsonrpc.CodeInvalidParams, "invalid skills cursor")

	f.key = "invalid"
	for _, req := range []struct {
		method, name string
		params       map[string]any
	}{
		{"skills/list", "", nil},
		{"skills/get", "", map[string]any{"uri": publishSkillURI}},
		{"resources/read", publishSkillURI, map[string]any{"uri": publishSkillURI}},
	} {
		if w := mcpPost20260728(t, f, req.method, req.name, req.params, true); w.Code != 401 {
			t.Errorf("%s without a valid key: %d", req.method, w.Code)
		}
	}
}
