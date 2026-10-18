# Security

Do not open a public issue containing credentials, protected release URLs,
private files, request bodies, backups or log excerpts with personal data.
Use the repository's private vulnerability reporting channel if it is enabled;
otherwise contact the maintainer privately before publishing exploit details.

Review [the security model](docs/ARCHITECTURE.md) before installation. A leaked
agent key manages every release on its instance. Revoke it locally, provision a
new named key into the client secret store, and inspect private audit logs.
Never upload an incident backup or a secret handoff to the public repository.

No supported interface exposes shell execution, arbitrary URL fetching,
credential administration or uploaded code execution. If a proposed fix adds
one of those, it is not an acceptable shortcut.

Run tests and dependency vulnerability checks before upgrades. A successful scan
or test run is not a penetration-test certification or a guarantee of safety.
Initial releases are pre-1.0: use current tested source and keep operator backups.
