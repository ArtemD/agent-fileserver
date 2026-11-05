package main

import (
	"html"
	"net/http"
)

// Every refusal tells the caller (usually an AI agent) what happened, why, and
// what to do next. The error string stays short and stable; "hint" is the next
// step; "entry" and "reason" name the offending archive member when there is
// one. Hints never contain secrets, server paths or request content: they are
// static text, and entry is the caller's own member name, bounded.
type apiErrorBody struct {
	Error     string `json:"error"`
	Entry     string `json:"entry,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Hint      string `json:"hint,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// visitorError answers a person in a browser (a refused release request from
// Caddy's forward_auth) with a small readable page instead of JSON. Status,
// headers and the stable error string are the same as apiError's; the page
// shows a heading, the hint and the request ID. All text is static and
// escaped; the page loads nothing and runs nothing.
func visitorError(w http.ResponseWriter, status int, id, msg string) {
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	title := visitorTitles[status]
	if title == "" {
		title = "Not available"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>` + html.EscapeString(title) + `</title>
<style>:root{color-scheme:light dark}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:Canvas;color:CanvasText}
main{max-width:34rem;margin:15vh auto 0;padding:0 16px}h1{font-size:1.5rem;margin:0 0 .5rem}p{margin:0 0 1rem}
small{opacity:.6;overflow-wrap:anywhere}</style></head>
<body><main><h1>` + html.EscapeString(title) + `</h1><p>` + html.EscapeString(errorHints[msg]) + `</p>
<p><small>Request ID: ` + html.EscapeString(id) + `</small></p></main></body></html>
`))
}

// Headings of the visitor pages, by status.
var visitorTitles = map[int]string{
	401: "Password required",
	404: "Link not found",
	429: "Please try again shortly",
}

func apiError(w http.ResponseWriter, status int, id, msg string) {
	apiErrorDetail(w, status, id, msg, "", "")
}

// apiErrorDetail adds the member name and the specific reason to a refusal.
func apiErrorDetail(w http.ResponseWriter, status int, id, msg, entry, reason string) {
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	apiJSON(w, status, apiErrorBody{Error: msg, Entry: entry, Reason: reason, Hint: errorHints[msg], RequestID: id})
}

const (
	hintServer = "This is a server-side problem, not an error in your request. Retry once; if it happens again, " +
		"stop and tell the server owner, quoting request_id."
	hintNothingPublished = " Nothing was published, so retrying with the same idempotency_key and bytes is safe."
	hintNewTicket        = " Each ticket works once: call begin_upload again for a new ticket before retrying."
	hintCheckReleases    = "Call list_releases to see whether the release exists. If it does, use it; " +
		"if not, publish again with a NEW idempotency_key."
	hintPassword = "Choose a password of 8 to 72 UTF-8 bytes with no control characters (no tabs or newlines), " +
		"or leave password out to publish publicly. reset_password generates one for an existing release."
	hintLabel = "label is optional: up to 200 characters of UTF-8 text without control characters (no newlines or tabs)."
	hintKey   = "Pass idempotency_key: 16 to 128 characters from A-Z, a-z, 0-9, '-' and '_' (a random UUID works). " +
		"Use a new key for each new publish; reuse a key only to retry the same bytes."
	hintInternalAPI = "This is an internal transport error. Publish with the publish_archive, publish_files or begin_upload " +
		"MCP tools; if you already did, report it to the server owner with request_id."
	hintLimits = "Check server_info: max_upload_bytes is the archive size, max_extract_bytes the unpacked total and " +
		"max_entries the file count for inline MCP publishes; the upload block holds the larger begin_upload limits. " +
		"Remove unused files, split the site, or use begin_upload for content over the inline limits."
	hintDisk = "The server is low on free disk space or inodes (server_info shows the disk block: available_bytes, " +
		"largest_file_upload_bytes and largest_archive_upload_bytes say what fits now). " +
		"Your request is fine. Delete releases you no longer need with delete_release, or ask the server owner to free space, then retry."
	hintTimeout = "The request ran longer than request_timeout_seconds (server_info) or the client disconnected. " +
		"Call list_releases to check; if nothing was published, retry with the same idempotency_key and bytes, " +
		"or use begin_upload for large content."
	hintPacking = "Text-heavy sites: tar.gz ('tar -czf site.tar.gz -C dist .') or ZIP ('cd dist && zip -r ../site.zip .'). " +
		"Already-compressed files such as video, images, audio or PDF: plain tar ('tar -cf media.tar -C dir .') or a stored ZIP " +
		"('zip -0 -r ../media.zip .'); compressing them again only costs time."
	hintArchive = "Fix the named entry and publish again; the same idempotency_key is fine because nothing was published. " +
		"Archives may be ZIP, tar or tar.gz, flat or in one wrapper directory, with only regular files and directories: " +
		"no links, devices, absolute paths, '..' or duplicate names."
	hintMalformed = "Send a complete ZIP, tar or tar.gz file, unmodified. Rebuild it (for example " +
		"'tar -czf site.tar.gz -C dist .' or 'cd dist && zip -r ../site.zip .'), check it with 'tar -tzf' or 'unzip -t', " +
		"and make sure the base64 or upload carries the exact file bytes."
	hintRefused = "The publisher accepts only clean, built static output. Remove or rename the named entry and publish again " +
		"(nothing was published, so the same idempotency_key is fine). Not allowed: dotfiles and .env, node_modules, " +
		"credentials/secrets files, private keys, .pem/.key containers, source maps, server-side scripts " +
		"(.php, .py, .rb, .sh, ...), links, special files, and .gz/.br files next to their original."
)

// errorHints maps each stable error string to its next step. A Go test
// (TestEveryErrorHasHint) fails if an apiError or mcpFailure literal lacks one.
var errorHints = map[string]string{
	// Routing and authentication.
	"not found": "The path, release or file does not exist. Check the URL or token; agents can call list_releases " +
		"for current tokens. A deleted release cannot be restored.",
	"release not found": "No active release of your account has this token (it may have been deleted or have expired). Call list_releases for current tokens; " +
		"a deleted release cannot be restored, so publish it again, without token, if you still need it. Nothing was changed.",
	"invalid release token": "token must be the 22-character token of an existing release, as list_releases shows it. " +
		"Leave token out to publish a new release. Nothing was published.",
	"expires_in_days must be an integer from 0 to 3650": "Pass expires_in_days as a whole number of days from now: 1 to 3650 to have the release " +
		"deleted automatically, or 0 to keep it forever. Leave it out for the server default (default_expiry_days in server_info) " +
		"or, on an update, to keep the current expiry. Nothing was changed.",
	"invalid upload_from_computer arguments": "upload_from_computer takes only optional label, spa, password, token and expires_in_days, " +
		"with the same rules as begin_upload. Nothing was changed.",
	"invalid set_expiry arguments":     "set_expiry takes exactly token (from list_releases) and expires_in_days (0 to 3650, 0 = never expire). Nothing was changed.",
	"could not update release expiry":  hintServer + " Call release_info to see the current expires_at.",
	"method not allowed":               "The HTTP method does not fit this endpoint (see the Allow header). Use the MCP tools, which choose the method for you.",
	"origin not allowed":               "Browser requests from other websites are refused. Call this endpoint from an MCP client or curl, without an Origin header.",
	"too many authentication failures": "Too many invalid keys or tickets from this client in the last minute. Wait 60 seconds (Retry-After) and retry once with a valid credential; do not retry in a loop.",
	"authentication required": "Send the agent key as 'Authorization: Bearer KEY', or as 'X-Auth-Token: KEY' when the MCP host reserves " +
		"Authorization. Only the server owner can create keys (docker compose run --rm -T admin token create); never put a key in chat or tool arguments.",
	"a valid, unused upload ticket from begin_upload is required": "The upload ticket is missing, expired (tickets last 30 minutes), already used, " +
		"or its agent key was revoked. Call begin_upload again and run the curl command it returns unchanged, including the Authorization header.",
	"expected one JSON-RPC request object":                            "Send exactly one JSON-RPC 2.0 request object per HTTP POST. This is an MCP client problem, not a problem with your content.",
	"expected one JSON-RPC request object; batches are not supported": "Send one JSON-RPC 2.0 request object per HTTP POST instead of an array; this server does not accept batches.",
	"MCP busy; retry with the same arguments and idempotency key":     "Too many MCP calls are running at once. Wait a few seconds and repeat the same call; publish retries with the same idempotency_key cannot create duplicates.",
	"MCP request exceeds encoded archive and JSON overhead limit": "The tool call is too large to publish inline. Call begin_upload with the file's size and sha256, " +
		"then PUT the raw file with the returned curl command.",
	"missing authenticated request": hintServer,
	"MCP output limit exceeded":     "The result was too large to return over MCP. Call release_info or list_releases to check the state instead of repeating the call.",
	"management operation failed":   hintServer,
	"invalid release metadata":      hintServer,

	// Tool arguments.
	"invalid tool arguments": "Check the arguments against the tool schema. Release tools take token: the 22-character token from list_releases " +
		"or a publish result; set_password also takes password. Unknown or misspelled fields are rejected.",
	"this tool takes no arguments": "Call this tool with an empty arguments object: {}.",
	"invalid begin_upload arguments": "Check names and types against the schema: size (integer bytes), sha256 (64 lowercase hex), idempotency_key, " +
		"and optional filename, label, password, spa. Unknown or misspelled fields are rejected.",
	"invalid upload request": "begin_upload takes size, sha256 and idempotency_key, plus optional filename, label, password and spa. " +
		"Check names and JSON types; unknown fields are rejected.",
	"invalid publish arguments; supply a URL-safe idempotency_key of 16..128 characters": hintKey + " " + hintLabel +
		" Unknown or misspelled fields are rejected.",
	"invalid metadata or viewer password":                            "label must be at most 200 characters and password at most 72 bytes. " + hintPassword,
	"a URL-safe Idempotency-Key of 16 to 128 characters is required": hintKey,
	"a URL-safe idempotency_key of 16 to 128 characters is required": hintKey,
	"sha256 must be 64 lowercase hex characters": "Pass the SHA-256 of the exact file you will upload as 64 lowercase hex characters " +
		"(sha256sum FILE | cut -d' ' -f1).",
	"size must be between 1 byte and the server's upload limit": "Pass the exact file size in bytes (stat -c %s FILE). server_info upload.max_bytes " +
		"is the largest allowed upload; an empty file cannot be published.",
	"invalid label": hintLabel,
	"filename must be a plain file name without slashes, dot prefix, secrets or server-side script extensions": "filename is only for publishing one " +
		"downloadable file: a plain name such as report.pdf, with no '/', not starting with '.', and not a key, secret or server-side script " +
		"(.php, .py, .sh, ...). Leave filename out to upload a ZIP, tar or tar.gz website.",
	"spa requires a website archive with a root index.html, not a single file": "Leave spa out for a single file, or leave filename out and upload " +
		"a site archive with index.html at its top level.",
	"invalid archive arguments or decoded archive exceeds limit": "Pass archive_base64 (standard padded base64 of the whole file, no line breaks) " +
		"and no files. If the archive is larger than server_info max_upload_bytes, use begin_upload instead.",
	"invalid files arguments or entry limit exceeded": "Pass files as a non-empty array (at most server_info max_entries items) and no archive_base64. " +
		"For larger sites, pack them as ZIP or tar.gz and use publish_archive or begin_upload.",
	"MCP files array exceeds the 5000-entry limit": "Pack the site as a ZIP or tar.gz and publish it with publish_archive or begin_upload.",
	"invalid files": "Fix the named file and call publish_files again (nothing was published, so the same idempotency_key is fine). " +
		"Each path is relative like 'css/site.css' with no leading '/', no '..', no '.' prefixes and no duplicates, and each file has exactly one of " +
		"text (valid UTF-8) or content_base64 (standard padded base64, no line breaks).",

	// Passwords.
	"password must be 8 to 72 UTF-8 bytes without control characters": hintPassword,
	"invalid viewer password":                       hintPassword,
	"invalid password request":                      "set_password takes a password of 8 to 72 UTF-8 bytes. " + hintPassword,
	"password removal requires DELETE":              "To make the release public, call remove_password. set_password needs a non-empty password.",
	"could not generate password":                   hintServer,
	"could not update release policy":               hintServer + " Call release_info to see the release's current protection before retrying.",
	"new viewer login attempts temporarily limited": "Too many viewer sign-ins for this release from your network. Wait a minute and try again.",
	"viewer authentication busy; retry shortly":     "The server is checking many passwords at once. Wait a few seconds and reload.",
	"viewer authentication required": "This link is protected with a password. Reload the page and sign in with the username viewer " +
		"and the password you were given. If you do not have the password, ask the person who sent you the link.",
	"link not found": "This link does not exist, has expired or was removed. Check that you copied the whole link, " +
		"or ask the person who sent it for a new one.",

	// Publishing.
	"publish attempt limit reached": "This agent key used all publish attempts for the window (server_info publish_limit and publish_window_seconds); " +
		"failed attempts count too. Wait for the window to pass, and fix the cause of earlier failures before retrying.",
	"publisher busy; retry with the same key and bytes":                    "Another publish is running. Wait a few seconds and retry with the same idempotency_key and identical bytes; this cannot create a duplicate.",
	"publisher busy; retry with a new ticket and the same idempotency_key": "Another publish is running." + hintNewTicket + " Use the same idempotency_key and the same file.",
	"another upload is in progress; call begin_upload again later":         "Only one upload runs at a time. Wait until it finishes." + hintNewTicket,
	"too many pending uploads; use or let them expire (30 minutes)": "The server holds at most upload.max_pending_tickets unused tickets (server_info). " +
		"Use the tickets you already have, or wait up to 30 minutes for them to expire.",
	"could not create upload ticket":            hintServer,
	"insufficient free disk space":              hintDisk,
	"could not maintain private API state":      hintServer,
	"could not stage upload":                    hintServer + hintNothingPublished,
	"could not read staged upload":              hintServer + hintNothingPublished,
	"could not stage archive":                   hintServer + hintNothingPublished,
	"could not stage files":                     hintServer + hintNothingPublished,
	"could not read staged files":               hintServer + hintNothingPublished,
	"could not persist publish intent":          hintServer + hintNothingPublished,
	"expected multipart metadata then artifact": hintInternalAPI,
	"metadata must be the first part":           hintInternalAPI,
	"artifact must be the second part":          hintInternalAPI,
	"unexpected data after multipart body":      hintInternalAPI,
	"invalid metadata":                          hintInternalAPI,
	"invalid metadata or label":                 hintLabel + " " + hintPassword,
	"idempotency key was used with a different body": "This idempotency_key already published different bytes or a different password in the last 24 hours. " +
		"Use a new idempotency_key for new content; reuse a key only to retry exactly the same bytes and password.",
	"previous publish outcome is ambiguous; list your uploads before retrying": "An earlier attempt with this idempotency_key may or may not have published. " + hintCheckReleases,
	"previous publish outcome is ambiguous; list your uploads":                 "The record of an earlier attempt with this idempotency_key is unreadable. " + hintCheckReleases,
	"original release is no longer active":                                     "This idempotency_key published a release that has since been deleted. Publish again with a new idempotency_key.",
	"publish failed; list your uploads before retrying with a new key":         "Publishing failed part way and may or may not have activated. " + hintCheckReleases + " Quote request_id if it keeps failing.",
	"publish outcome is ambiguous; list your uploads before retrying":          "The release may have been published, but its record could not be saved. " + hintCheckReleases,
	"publisher refused artifact":                                               hintRefused,
	"SPA requires a directory with a root index.html": "Use spa only for a website whose index.html is at the top level (or inside one wrapper " +
		"directory). Otherwise publish without spa.",
	"request cancelled or timed out":   hintTimeout,
	"upload took too long":             "The upload did not finish within the 60-minute receive window. Check the connection and file size." + hintNewTicket,
	"upload or archive limit exceeded": hintLimits,
	"body is larger than the size declared to begin_upload": "Upload exactly the file you described. Recompute size (stat -c %s FILE) and sha256 " +
		"(sha256sum FILE) from the file on disk and PUT that same file." + hintNewTicket,
	"body length differs from the size declared to begin_upload": "Upload exactly the file you described. Recompute size (stat -c %s FILE) and sha256 " +
		"(sha256sum FILE) from the file on disk and PUT that same file." + hintNewTicket,
	"body is shorter than the size declared to begin_upload": "The upload ended early or the file is smaller than declared. Recompute size and sha256 " +
		"from the file on disk and check the connection." + hintNewTicket,
	"body does not match the sha256 declared to begin_upload": "The bytes received differ from the declared sha256. Recompute it from the exact file " +
		"(sha256sum FILE), make sure nothing rewrote the file, and upload that file." + hintNewTicket,

	// Archives.
	"unsafe archive entry": hintArchive,
	"malformed archive":    hintMalformed,
	"unsupported archive format": "Repack the files as ZIP, tar or tar.gz and publish again; nothing was published, so the same " +
		"idempotency_key is fine. " + hintPacking,

	// Releases and downloads.
	"could not list releases":       hintServer,
	"could not read release policy": hintServer,
	"could not delete release":      hintServer + " Call release_info to see whether the release still exists.",
	"invalid stored release":        hintServer,
	"release file not found":        hintServer,
	"could not download release":    hintServer,
	mcpTooLarge:                     "download_release returns files only up to 1 MiB inline. Keep your own copy of large files; release_info still shows the release's metadata.",
}
