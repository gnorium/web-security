# Repository guidance

This directory is its own Git repository. The parent Gnorium workspace is not a repository; run Git commands here and inspect sibling repositories separately.

- Preserve unrelated working changes. When renaming an internal API, update callers in sibling packages rather than leave obsolete aliases.
- Run focused checks for the changed behavior. Do not run full server/browser suites unless requested.
- Keep build caches and `.build` directories. Diagnose build/toolchain errors before rebuilding; do not wipe caches to troubleshoot.
- Batch related changes before building. Deployment requires an explicit user request; a local build or server restart is not deployment.
- If committing authorized work, omit attribution trailers and push normally after the commit; never force-push.

## Data and history

- Audit/event logs and historical model traces are immutable. Never delete or rewrite audit rows, even in development.
- Development-only cleanup does not belong in migrations. Changes required on every deployment belong in idempotent migrations; production is live history.
- Secrets come from configured environment/secrets storage, never defaults. Keep credentials, raw IP addresses, provider tokens, and personal data out of logs and URLs.
- Use the established data-protection sealing and keyed hashing APIs. Preserve account deletion's retained contribution identity; classify new user-linked tables in the deletion/retention rules.

## Security interfaces

Use the established authenticated encryption, keyed hashing, and verification primitives. Keep privacy guarantees and consuming server policies consistent with the implementation; no default credentials or provider-token persistence.
