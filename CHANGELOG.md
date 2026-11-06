# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release adds or changes behaviour and a patch release
only fixes bugs; upgrade notes call out anything an operator or agent must do.

Each release on GitHub also lists every commit and the issues it closed.

## [Unreleased]

### Security

- Operators: stop both containers and keep a full data backup before upgrading.
  Release updates use immutable content versions selected during authorization;
  existing URLs remain unchanged. Follow the
  [upgrade and rollback steps](docs/INSTALL.md#upgrades)
  ([GHSA-2qfg-m2gw-79hp](https://github.com/ArtemD/agent-fileserver/security/advisories/GHSA-2qfg-m2gw-79hp)).

### Fixed

- Downloads finish building before returning success, so concurrent updates or
  deletions cannot produce an incomplete successful archive. Upload cancellation
  accurately describes uncertain publication and preserves the complete request
  for retry. Upload completion messages use the MCP Apps content array expected
  by hosts. No client changes are required
  ([#35](https://github.com/ArtemD/agent-fileserver/issues/35)).

## [0.5.2] - 2026-11-05

### Fixed

- Visitors who cancel the password prompt of a protected release, open an
  unknown or expired link, or hit the visitor sign-in limits now get a short,
  readable HTML page instead of a raw JSON API error. Status codes and the
  browser's password prompt are unchanged; nothing to do on upgrade
  ([#34](https://github.com/ArtemD/agent-fileserver/issues/34)).

## [0.5.1] - 2026-11-03

### Changed

- The service image and the one-shot `init` container run on Alpine 3.24.3
  (was 3.24.2). The upgrade is the usual rebuild; nothing else to do
  ([#14](https://github.com/ArtemD/agent-fileserver/pull/14),
  [#15](https://github.com/ArtemD/agent-fileserver/pull/15),
  [#33](https://github.com/ArtemD/agent-fileserver/issues/33)).

## [0.5.0] - 2026-11-03

### Added

- Accounts. Every key belongs to an account, and a key sees and manages only
  its account's releases: `list_releases` and its totals show only them, and
  `release_info`, `download_release`, `delete_release`, the password tools,
  `set_expiry` and updates with `token` (also through `begin_upload` and
  `upload_from_computer`) answer `release not found` for another account's
  release, the same as for an unknown token. Give a teammate a key in their own
  account so they can publish without seeing or touching yours.
  `server_info` reports `account`, and `token list` shows each key's account.
  Release links themselves are unchanged and stay public (or
  password-protected) for anyone who has them
  ([#32](https://github.com/ArtemD/agent-fileserver/issues/32)).

### Changed

- `token create` requires `--account NAME`. Operators: add `--account owner`
  to scripts that create your own keys, and use a new account name for anyone
  else. Existing keys and releases are in account `owner` and keep working
  with no migration; nothing changes for clients. If someone else already has
  a key, it is in `owner` and still manages your releases: give them a key in
  their own account and revoke the old one. Steps, checks and rollback:
  [Upgrading to the release with accounts](docs/INSTALL.md#upgrades)
  ([#32](https://github.com/ArtemD/agent-fileserver/issues/32)).

## [0.4.2] - 2026-11-03

### Fixed

- Panels are usable by touch. On phones and tablets every button, field and
  menu in the release card, the releases dashboard and the upload panel is now
  at least 44px (they were 25 to 32px, the dashboard's row buttons the
  smallest), the dashboard's row buttons sit further apart, and the filter and
  sort fields use 16px text so iOS no longer zooms the page when they are
  tapped. Desktop sizes are unchanged. Nothing to do for clients or operators
  ([#31](https://github.com/ArtemD/agent-fileserver/issues/31)).

## [0.4.1] - 2026-11-02

### Fixed

- Release URLs follow the current domain. Every `url` in MCP results is now
  built from `FSERVER_BASE_URL` (that is, `FSERVER_DOMAIN`) when the result is
  sent, not taken from the value stored at publish time, so after a domain
  change old releases stop reporting the old host (and the panels, which
  open only links on the current domain, show them again). The `url` field and the
  manifest format are unchanged and no migration runs; operators who change the
  domain should keep the old hostname pointed at the server while old links are
  still in use ([#26](https://github.com/ArtemD/agent-fileserver/issues/26)).
- Panels report their content height. They sent the iframe's own height
  (`scrollHeight` of the root, which is never below the viewport), so a host
  could grow a panel but never shrink it, and they resent the same size on
  every layout change. They now measure the content like the ext-apps SDK and
  send `ui/notifications/size-changed` only when the size changed and only after
  the handshake. Nothing to do for clients or operators
  ([#28](https://github.com/ArtemD/agent-fileserver/issues/28)).
- The releases dashboard fits a phone. Below 700px each release is a card
  (name and token, then size, access, date and expiry, then the buttons)
  instead of a six-column table that hid Expires and the buttons behind a
  sideways scroll in the Claude mobile app. Nothing to do for clients or
  operators ([#30](https://github.com/ArtemD/agent-fileserver/issues/30)).

## [0.4.0] - 2026-11-02

### Added

- Panels in the chat (MCP Apps). Claude and other hosts that support MCP Apps
  show an interactive panel next to some results; other clients get the same
  text results as before. A release card for `publish_files`,
  `publish_archive`, `release_info`, `set_expiry`, `set_password` and
  `remove_password` shows the link with copy and open buttons, access, size
  and expiry, with buttons to keep the release 30 days, 1 year or forever
  ([#23](https://github.com/ArtemD/agent-fileserver/issues/23)). A dashboard for `list_releases` shows totals and every release,
  sorts and filters them, and keeps or deletes a release (delete needs a
  second click) ([#24](https://github.com/ArtemD/agent-fileserver/issues/24)).
- `upload_from_computer`: opens a drop zone in the chat where you pick a file
  from your own computer. The panel hashes it, gets a one-time ticket from
  `begin_upload`, uploads it with a progress bar and tells the agent the URL
  ([#25](https://github.com/ArtemD/agent-fileserver/issues/25)).

### Changed

- `PUT /_upload` answers CORS (`OPTIONS` preflight, `Access-Control-Allow-Origin: *`,
  no credentials) and no longer refuses requests with a foreign `Origin`, so
  the upload panel can send the file from the host's sandbox. The one-time
  ticket stays the only credential, management keys stay refused there, and
  `/mcp` keeps its strict origin check ([#25](https://github.com/ArtemD/agent-fileserver/issues/25)).
- The service image embeds the panels from `ui/`; rebuild the image when you
  upgrade, as usual ([#23](https://github.com/ArtemD/agent-fileserver/issues/23)).

## [0.3.0] - 2026-11-02

### Added

- Releases expire. New releases are deleted automatically after 60 days
  unless the agent passes `expires_in_days` (1 to 3650, or 0 for never) to
  `publish_files`, `publish_archive` or `begin_upload`. The new `set_expiry`
  tool changes or removes the expiry later. Every release view shows
  `expires_at` (`null` for never), publish results carry a `notice` that says
  when the release goes and how to keep it, and `server_info` reports
  `default_expiry_days`. Visitors get 404 from the moment a release expires; a
  sweeper deletes it within 10 minutes. Operators set the default with
  `FSERVER_DEFAULT_EXPIRY_DAYS` (0 turns the default expiry off). Releases
  published before this version have no expiry: upgrading deletes nothing
  ([#19](https://github.com/ArtemD/agent-fileserver/issues/19)).
- Update a release in place: pass `token` of an existing release to
  `publish_files`, `publish_archive` or `begin_upload` and the new content
  replaces the old atomically under the same URL. The visitor password,
  label and expiry are kept unless the call sets new ones; `updated_at` shows
  when ([#20](https://github.com/ArtemD/agent-fileserver/issues/20)).
- `server_info` has a `disk` block: free and total bytes, free inodes, the
  reserve, and the largest file and archive upload that fit right now
  ([#21](https://github.com/ArtemD/agent-fileserver/issues/21)).
- `list_releases` reports `count`, `total_bytes`, `truncated` and
  `expiring_within_7_days` over all releases ([#22](https://github.com/ArtemD/agent-fileserver/issues/22)).

### Changed

- `list_releases` returns an object instead of an array; the releases are in
  its `releases` field. Clients that read the array must read `.releases`
  ([#22](https://github.com/ArtemD/agent-fileserver/issues/22)).
- Public releases are served with `Cache-Control: public, no-cache` instead
  of `public, max-age=3600`, so browsers and caches revalidate and show an
  update at once ([#20](https://github.com/ArtemD/agent-fileserver/issues/20)).
- `publish_files`, `publish_archive` and `begin_upload` are annotated as
  destructive, because with `token` they replace content ([#20](https://github.com/ArtemD/agent-fileserver/issues/20)).

## [0.2.0] - 2026-11-01

### Added

- `begin_upload` MCP tool and ticket-only `PUT /_upload`: publish files and
  site archives up to 1 GiB (configurable) by sending raw bytes from a shell
  with a one-time, 30-minute ticket, so the management key never leaves the
  MCP connector ([#10](https://github.com/ArtemD/agent-fileserver/issues/10)).
- Builds are stamped with their version. Compose passes `FSERVER_VERSION` (set
  by `scripts/exe-dev-up.sh` and the documented upgrade command from
  `git describe`) into the image, and `server_info` returns `version`
  ([#16](https://github.com/ArtemD/agent-fileserver/issues/16)).
- This changelog, and release notes taken from it
  ([#16](https://github.com/ArtemD/agent-fileserver/issues/16)). A release can
  also be cut by running the Release workflow on `main` with a version, which
  creates the tag after the tests pass
  ([#17](https://github.com/ArtemD/agent-fileserver/issues/17)).
- Every error response, over HTTP and MCP, carries a `hint` with the next step
  for the agent, and archive and publisher refusals name the offending `entry`
  and the `reason` ([#11](https://github.com/ArtemD/agent-fileserver/issues/11)).
- xz, zstd, bzip2, 7z, rar, lzip and lz4 uploads are recognised and refused as
  `unsupported archive format`, naming the detected format
  ([#12](https://github.com/ArtemD/agent-fileserver/issues/12)).

### Changed

- A release made from a single `index.html` reports the release root
  (`/TOKEN/`) as its `url`. Tool descriptions and docs now say that single
  files are served with their content type and that a lone `index.html` is a
  one-page website ([#13](https://github.com/ArtemD/agent-fileserver/issues/13)).
- Archive refusals are typed: `unsafe archive entry`, `malformed archive` and
  `unsupported archive format` replace `malformed or unsafe upload archive`.
  Clients matching the old string must switch to the new ones
  ([#11](https://github.com/ArtemD/agent-fileserver/issues/11)).
- Tool descriptions say which archive format to use: tar.gz or ZIP for text,
  plain tar or `zip -0` for already-compressed media
  ([#12](https://github.com/ArtemD/agent-fileserver/issues/12)).

### Fixed

- Flat tar and tar.gz archives (files at the top level, or `./` entries as
  written by `tar -C dir .`) were always refused; they now publish like ZIP
  archives ([#11](https://github.com/ArtemD/agent-fileserver/issues/11)).

## [0.1.0] - 2026-10-30

### Added

- First release: a single-owner static file publisher managed only through
  remote MCP, running as Docker Compose with Caddy in front of a networkless
  Go service. Publishing of files and ZIP/tar/tar.gz sites, optional visitor
  passwords, per-agent keys administered from the host, and hardened
  containers.

[Unreleased]: https://github.com/ArtemD/agent-fileserver/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/ArtemD/agent-fileserver/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/ArtemD/agent-fileserver/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ArtemD/agent-fileserver/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/ArtemD/agent-fileserver/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ArtemD/agent-fileserver/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ArtemD/agent-fileserver/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ArtemD/agent-fileserver/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ArtemD/agent-fileserver/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ArtemD/agent-fileserver/releases/tag/v0.1.0
