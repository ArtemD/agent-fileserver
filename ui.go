package main

// MCP Apps panels (the official MCP UI extension, protocol 2026-01-26). Hosts
// that support it, such as Claude, render a tool's linked ui:// resource as an
// interactive panel in the chat; other clients keep using the text result.
// The panels are static files embedded in the binary. Each one is composed
// once at start: the shared bridge and styles are inlined and the configured
// base URL replaces a marker, JSON-encoded so it cannot break out of the
// script. Panels never receive server paths or secrets.
import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed ui/*.html ui/*.js ui/*.css
var uiFiles embed.FS

const (
	uiMIMEType     = "text/html;profile=mcp-app"
	uiReleaseURI   = "ui://agent-fileserver/release.html"
	uiReleasesURI  = "ui://agent-fileserver/releases.html"
	uiUploadURI    = "ui://agent-fileserver/upload.html"
	uiBaseMarker   = `"__FSERVER_BASE_URL__"`
	uiBridgeMarker = "/*FSERVER:BRIDGE*/"
	uiCSSMarker    = "/*FSERVER:BASE_CSS*/"
)

// uiToolPanels links tools to the panel that shows their result.
var uiToolPanels = map[string]string{
	"publish_files":        uiReleaseURI,
	"publish_archive":      uiReleaseURI,
	"release_info":         uiReleaseURI,
	"set_expiry":           uiReleaseURI,
	"set_password":         uiReleaseURI,
	"remove_password":      uiReleaseURI,
	"list_releases":        uiReleasesURI,
	"upload_from_computer": uiUploadURI,
}

// uiToolMeta is the _meta that links a tool to its panel. The flat
// "ui/resourceUri" key is the deprecated form some hosts still read.
func uiToolMeta(name string) mcp.Meta {
	uri, ok := uiToolPanels[name]
	if !ok {
		return nil
	}
	return mcp.Meta{"ui": map[string]any{"resourceUri": uri}, "ui/resourceUri": uri}
}

type uiPanel struct {
	uri, file, name, description string
	meta                         mcp.Meta
	html                         string
}

// uiComposePanel inlines the bridge and base styles into one panel and sets
// the base URL. It fails if a marker is missing, so a broken panel never ships.
func uiComposePanel(file, base string) (string, error) {
	read := func(name string) (string, error) {
		b, err := uiFiles.ReadFile("ui/" + name)
		return string(b), err
	}
	page, err := read(file)
	if err != nil {
		return "", err
	}
	bridge, err := read("bridge.js")
	if err != nil {
		return "", err
	}
	css, err := read("base.css")
	if err != nil {
		return "", err
	}
	if strings.Count(bridge, uiBaseMarker) != 1 || strings.Count(page, uiBridgeMarker) != 1 || strings.Count(page, uiCSSMarker) != 1 {
		return "", fmt.Errorf("panel %s: bridge, style or base URL marker missing", file)
	}
	// json.Marshal escapes <, > and & as < etc., so no "</script>".
	quoted, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	bridge = strings.Replace(bridge, uiBaseMarker, string(quoted), 1)
	page = strings.Replace(page, uiCSSMarker, css, 1)
	return strings.Replace(page, uiBridgeMarker, bridge, 1), nil
}

func uiPanels(base string) ([]uiPanel, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	panels := []uiPanel{
		{uri: uiReleaseURI, file: "release.html", name: "Release card",
			description: "One release: link, access, size and expiry, with copy, open and keep-longer buttons.",
			meta:        mcp.Meta{"ui": map[string]any{"prefersBorder": true, "permissions": map[string]any{"clipboardWrite": map[string]any{}}}}},
		{uri: uiReleasesURI, file: "releases.html", name: "Releases dashboard",
			description: "All releases with totals, sorting, filtering, keep-forever and delete.",
			meta:        mcp.Meta{"ui": map[string]any{"prefersBorder": true, "permissions": map[string]any{"clipboardWrite": map[string]any{}}}}},
		// The upload panel sends the file to PUT /_upload on this server.
		{uri: uiUploadURI, file: "upload.html", name: "Upload from computer",
			description: "Drop zone that uploads a file from the user's computer with a one-time ticket.",
			meta: mcp.Meta{"ui": map[string]any{"prefersBorder": true, "csp": map[string]any{"connectDomains": []string{origin}},
				"permissions": map[string]any{"clipboardWrite": map[string]any{}}}}},
	}
	for i := range panels {
		if panels[i].html, err = uiComposePanel(panels[i].file, base); err != nil {
			return nil, err
		}
	}
	return panels, nil
}

// addUIResources registers every panel as a ui:// resource. The metadata is
// on both the list entry and the read result, as hosts read either.
func addUIResources(server *mcp.Server, base string) error {
	panels, err := uiPanels(base)
	if err != nil {
		return err
	}
	for _, p := range panels {
		p := p
		server.AddResource(&mcp.Resource{URI: p.uri, Name: p.name, Description: p.description, MIMEType: uiMIMEType, Meta: p.meta},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: p.uri, MIMEType: uiMIMEType, Text: p.html, Meta: p.meta}}}, nil
			})
	}
	return nil
}
