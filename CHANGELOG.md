# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release adds or changes behaviour and a patch release
only fixes bugs; upgrade notes call out anything an operator or agent must do.

Each release on GitHub also lists every commit and the issues it closed.

## [Unreleased]

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

[Unreleased]: https://github.com/ArtemD/agent-fileserver/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ArtemD/agent-fileserver/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ArtemD/agent-fileserver/releases/tag/v0.1.0
