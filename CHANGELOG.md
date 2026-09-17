# Changelog

Notable changes, newest first. Releases are git tags; this file says what each tag contains.

## v0.1.0 — initial public release

**The Relying Party onboarding control plane: client lifecycle and verification-key minting, over a registry schema, behind an admin API key.**

It is deliberately small — no HTML, no operator login, no sessions, no background jobs. Onboarding a
Relying Party is entirely API calls. It is **never in the request path of a live verification**: it
prepares the registry data that the wallet-facing and session services read at runtime.

It owns no schema of its own. Every access to the shared registry goes through `SECURITY DEFINER`
stored procedures, as a role that holds no direct table grants.

### Running it

The image entrypoint is `["/server", "web"]`, with `["/server", "health"]` as the healthcheck
command — a compose or orchestrator file that also passes `command: ["web"]` would append a second
argument. Every setting is an environment variable with a safe default where one is possible; the
README lists them, and any secret can be supplied as `<NAME>_FILE` pointing at a mounted file instead.

### What it needs

Go **1.27.0** to build. Libraries at this release:

`go-eudi-rpcert` v0.0.6 · `go-platform-kit` v1.11.3 · `azugo.io/azugo` + `azugo.io/core` v0.38.1
