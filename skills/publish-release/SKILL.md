---
name: publish-release
description: "Publish or update a static site, archive, or file with Agent Fileserver. Choose an upload method, recover an interrupted publish, and share the link with its access and expiry."
---

# Publish with Agent Fileserver

Use this workflow when the user asks to publish a file or site, update a shared
release, or recover an interrupted publish.

## Choose the publishing method

- For a few small files whose contents you have, use `publish_files`. A single
  `index.html` gives the user a site at the release root.
- For a small ZIP, tar, or tar.gz site whose actual bytes fit in the tool call,
  use `publish_archive`.
- For a file only the user can access, offer `upload_from_computer` when the
  client can show the upload panel. Ask the user to choose the file there. The
  panel opens before anything is published.
- For a large file with an approved way to transfer its bytes, use
  `begin_upload`. The ticket starts the transfer workflow. If the client has
  neither the file bytes nor an upload panel, explain what the user needs to
  supply or suggest a client with the upload panel.

New releases are public unless the publish includes a visitor password. If
the intended audience is unclear, ask before publishing. Keep management
keys and upload tickets out of chat. When updating a shared release, use its
existing token. For a single-file release, use the same filename to keep
the exact link.

## Recover an interrupted publish

Reuse the same `idempotency_key`, file bytes, and publish options when
retrying the same operation. With an upload ticket, call `begin_upload`
again for a fresh ticket using those same inputs. In the upload panel, use
**Try again** to keep the original file and settings. If the server reports
an ambiguous outcome, inspect `list_releases` and, when needed,
`release_info` before starting another publish.

## Share the result

Wait for the release result. Use its `url`, `protected`, and `expires_at`
fields to tell the user the link, whether it needs a visitor password, and
when it expires. A null `expires_at` means the link has no scheduled expiry.
Use the returned date even when the user never set an expiry. For a change
to an existing link's expiry, use `set_expiry` when the user asks for it.
