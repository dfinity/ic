# WebMCP Demo Shop

A minimal e-commerce canister that demonstrates the full WebMCP pipeline:
`.did` → `webmcp.json` → AI agent tool calls.

## What's included

| File | Purpose |
|---|---|
| `backend.did` | Candid interface: products, cart, checkout |
| `src/lib.rs` | Business logic (per-caller carts, order IDs) |
| `src/main.rs` | `ic_cdk` entry points wiring `msg_caller()` |
| `dfx.json` | dfx config with `webmcp` section |
| `assets/index.html` | Minimal frontend loading `webmcp.js` |

## Running locally

```bash
# From this directory:
icp start --background
icp deploy

# Generate the WebMCP manifest from dfx.json:
ic-webmcp-codegen dfx --dfx-json dfx.json --out-dir assets/

# The manifest is now at assets/backend.webmcp.json
# Copy it to /.well-known/ for browser discovery:
cp assets/backend.webmcp.json assets/.well-known/webmcp.json
cp assets/backend.webmcp.js assets/webmcp.js

# Redeploy assets:
icp deploy frontend
```

Open the canister URL shown by `icp deploy` in Chrome 146+ with
WebMCP enabled. An AI agent can then discover and call:

- `list_products` — browse the catalog (certified query)
- `get_product` — get a single product by ID
- `get_cart` — view cart contents
- `add_to_cart` — add items (requires Internet Identity login)
- `checkout` — complete the purchase (requires Internet Identity login)

## Running tests

```bash
cargo test -p demo-backend
```
