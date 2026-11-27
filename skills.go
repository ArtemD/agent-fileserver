package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	skillsExtensionID = "io.modelcontextprotocol/skills"
	publishSkillName  = "publish-release"
	publishSkillURI   = "skill://" + publishSkillName + "/SKILL.md"
	publishSkillMIME  = "text/markdown"
)

//go:embed skills/publish-release/SKILL.md
var publishSkillMarkdown string

type skillFile struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}

type skillEntry struct {
	URI         string            `json:"uri"`
	Frontmatter map[string]string `json:"frontmatter"`
	Resources   []skillFile       `json:"resources"`
}

type skillListParams struct {
	mcp.ParamsBase
	Cursor string `json:"cursor"`
}

type skillGetParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type skillResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string       `json:"resultType"`
	Skills     []skillEntry `json:"skills,omitempty"`
	Skill      *skillEntry  `json:"skill,omitempty"`
}

func skillError(code int64, message string) error {
	data, _ := json.Marshal(map[string]string{"hint": errorHints[message]})
	return &jsonrpc.Error{Code: code, Message: message, Data: data}
}

func checkSkillVersion(params mcp.Params) error {
	if version, _ := params.GetMeta()[mcp.MetaKeyProtocolVersion].(string); version < "2026-07-28" {
		return &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound}
	}
	return nil
}

func addPublishSkill(server *mcp.Server) error {
	// This embedded file uses two fixed frontmatter fields. A JSON-quoted
	// string is also a YAML double-quoted scalar, so the description can
	// come from the Markdown without another runtime parser or a second copy.
	rest, prefixOK := strings.CutPrefix(publishSkillMarkdown, "---\nname: "+publishSkillName+"\ndescription: ")
	quoted, _, closeOK := strings.Cut(rest, "\n---\n")
	var description string
	if !prefixOK || !closeOK || json.Unmarshal([]byte(quoted), &description) != nil || description == "" {
		return errors.New("invalid embedded publishing skill frontmatter")
	}
	entry := skillEntry{
		URI:         publishSkillURI,
		Frontmatter: map[string]string{"name": publishSkillName, "description": description},
		Resources: []skillFile{{
			URI:    publishSkillURI,
			Digest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(publishSkillMarkdown))),
			Size:   len(publishSkillMarkdown),
		}},
	}
	cache := mcp.Cacheable{CacheScope: "private"}
	if err := mcp.AddReceivingCustomMethod(server, "skills/list",
		func(_ context.Context, _ *mcp.ServerSession, params *skillListParams) (*skillResult, error) {
			if err := checkSkillVersion(params); err != nil {
				return nil, err
			}
			if params.Cursor != "" {
				return nil, skillError(jsonrpc.CodeInvalidParams, "invalid skills cursor")
			}
			return &skillResult{ResultType: "complete", Cacheable: cache, Skills: []skillEntry{entry}}, nil
		}); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, "skills/get",
		func(_ context.Context, _ *mcp.ServerSession, params *skillGetParams) (*skillResult, error) {
			if err := checkSkillVersion(params); err != nil {
				return nil, err
			}
			if params.URI != publishSkillURI {
				return nil, skillError(jsonrpc.CodeInvalidParams, "skill not found")
			}
			return &skillResult{ResultType: "complete", Cacheable: cache, Skill: &entry}, nil
		}); err != nil {
		return err
	}

	server.AddResource(&mcp.Resource{
		URI: publishSkillURI, Name: publishSkillName, Description: description, MIMEType: publishSkillMIME,
	}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Cacheable: cache,
			Contents:  []*mcp.ResourceContents{{URI: publishSkillURI, MIMEType: publishSkillMIME, Text: publishSkillMarkdown}},
		}, nil
	})
	// Skills starts at 2026-07-28. DiscoverResult carries a copy of the
	// server's capabilities, so older initialize replies keep their shape.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if discovery, ok := result.(*mcp.DiscoverResult); ok && err == nil {
				discovery.Capabilities.AddExtension(skillsExtensionID, nil)
			}
			return result, err
		}
	})
	return nil
}
