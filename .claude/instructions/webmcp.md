# WebMCP Implementation Context

## What This Branch Is For
Branch `ianblenke/webmcp` implements WebMCP (Web Model Context Protocol) support for the Internet Computer. WebMCP is a W3C standard (Chrome 146+) that lets websites expose structured tools to AI agents via `navigator.modelContext`.

## Implementation Plan
See `rs/webmcp/IMPLEMENTATION_PLAN.md` for the full architecture, deliverables, and phased approach.

## Why IC Is Ideal for WebMCP
- **Candid interfaces** already define structured tool schemas (`.did` files)
- **Certified queries** provide cryptographically verified responses (BLS threshold signatures)
- **Internet Identity** enables scoped agent authentication via delegation chains
- **HTTP Gateway** already translates HTTP → canister calls

## Key Deliverables
1. `rs/webmcp/codegen/` — Rust: `.did` → `webmcp.json` + `webmcp.js`
2. `packages/ic-webmcp/` — TypeScript: bridge `navigator.modelContext` ↔ `@dfinity/agent`
3. Asset canister middleware — auto-serve `/.well-known/webmcp.json`
4. `dfx.json` integration — config-driven auto-generation

## Start Here
Begin with Phase 1: `rs/webmcp/codegen/` — the Candid-to-JSON-Schema mapper. Use the `candid_parser` crate to parse `.did` files. Test with `rs/ledger_suite/icp/ledger.did` as a fixture.

## WebMCP References
- Chrome blog: https://developer.chrome.com/blog/webmcp-epp
- W3C spec: https://webmcp.link/
- Technical guide: https://dev.to/czmilo/chrome-webmcp-the-complete-2026-guide-to-ai-agent-protocol-1ae9
