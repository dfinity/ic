# ic-webmcp-codegen

Command-line tool and Rust library that generates [WebMCP](https://webmcp.link/) tool manifests from Internet Computer Candid interface definitions.

Given a `.did` file (or a `dfx.json` project), it produces:

- `webmcp.json` — tool manifest for AI agent discovery (served at `/.well-known/webmcp.json`)
- `webmcp.js` — browser registration script (served at `/webmcp.js`)

## Building

```bash
# From the IC repository root:
cargo build -p ic-webmcp-codegen --release
```

The binary is placed at `target/release/ic-webmcp-codegen`.

## Usage

The tool has two subcommands: `did` for a single Candid file, and `dfx` for a full dfx project.

### `did` — from a single .did file

```bash
ic-webmcp-codegen did \
  --did path/to/canister.did \
  --canister-id ryjl3-tyaaa-aaaaa-aaaba-cai \
  --name "ICP Ledger" \
  --description "ICP token ledger implementing ICRC-1/2/3" \
  --expose icrc1_balance_of,icrc1_transfer \
  --require-auth icrc1_transfer \
  --certified icrc1_balance_of \
  --out-manifest webmcp.json \
  --out-js webmcp.js
```

| Flag | Description |
|---|---|
| `--did` | Path to the Candid `.did` file (required) |
| `--out-manifest` | Output path for `webmcp.json` (default: `webmcp.json`) |
| `--out-js` | Output path for `webmcp.js` (default: `webmcp.js`) |
| `--canister-id` | Canister principal ID to embed in the manifest |
| `--name` | Human-readable name shown to AI agents |
| `--description` | Description for AI agents |
| `--expose` | Comma-separated list of methods to include. Omit to include all. |
| `--require-auth` | Comma-separated methods that require Internet Identity authentication |
| `--certified` | Comma-separated query methods that support certified responses |
| `--no-js` | Skip generating `webmcp.js` |

### `dfx` — from a dfx.json project

```bash
ic-webmcp-codegen dfx \
  --dfx-json dfx.json \
  --out-dir .webmcp/
```

Reads the `webmcp` section from each canister in `dfx.json` and generates `<canister>.webmcp.json` and `<canister>.webmcp.js` for every enabled canister.

Also auto-discovers `canister_ids.json` or `.dfx/<network>/canister_ids.json` to embed canister principals.

| Flag | Description |
|---|---|
| `--dfx-json` | Path to `dfx.json` (default: `./dfx.json`) |
| `--canister-ids` | Path to `canister_ids.json` (auto-discovered if absent) |
| `--network` | Network to look up in `canister_ids.json` (default: `ic`) |
| `--out-dir` | Output directory (default: `.webmcp/`) |
| `--no-js` | Skip generating `.webmcp.js` files |

## dfx.json Configuration

Add a `webmcp` section to any canister in `dfx.json`:

```json
{
  "canisters": {
    "backend": {
      "type": "rust",
      "candid": "backend.did",
      "webmcp": {
        "enabled": true,
        "name": "My DApp",
        "description": "Description for AI agents",
        "expose_methods": ["get_items", "add_to_cart", "checkout"],
        "require_auth": ["add_to_cart", "checkout"],
        "certified_queries": ["get_items"],
        "descriptions": {
          "get_items": "List available products with prices",
          "add_to_cart": "Add a product to the shopping cart",
          "checkout": "Complete purchase with current cart contents"
        },
        "param_descriptions": {
          "add_to_cart.product_id": "The unique product identifier",
          "add_to_cart.quantity": "Number of items to add (default 1)"
        }
      }
    }
  }
}
```

| Field | Type | Description |
|---|---|---|
| `enabled` | bool | Whether to generate for this canister. Default: `true`. |
| `name` | string | Human-readable name. Default: canister name from dfx.json. |
| `description` | string | Description shown to AI agents. |
| `expose_methods` | string[] | Which service methods to expose. Omit to expose all. |
| `require_auth` | string[] | Methods requiring Internet Identity login. |
| `certified_queries` | string[] | Query methods with certified responses. |
| `descriptions` | object | Per-method descriptions (key: method name). |
| `param_descriptions` | object | Per-parameter descriptions (key: `"method.param"`). |

## Library API

The crate can also be used as a Rust library:

```rust
use ic_webmcp_codegen::{Config, generate_manifest};
use std::collections::BTreeMap;

let config = Config {
    did_file: "ledger.did".into(),
    canister_id: Some("ryjl3-tyaaa-aaaaa-aaaba-cai".into()),
    name: Some("ICP Ledger".into()),
    description: Some("ICP token ledger".into()),
    expose_methods: None,          // None = all methods
    require_auth: vec!["transfer".into()],
    certified_queries: vec!["account_balance".into()],
    method_descriptions: BTreeMap::new(),
    param_descriptions: BTreeMap::new(),
};

let manifest = generate_manifest(&config)?;
let json = serde_json::to_string_pretty(&manifest)?;
std::fs::write("webmcp.json", json)?;
```

### From dfx.json

```rust
use ic_webmcp_codegen::{configs_from_dfx_json, generate_manifest};

let configs = configs_from_dfx_json("dfx.json".as_ref(), None)?;
for (canister_name, config) in configs {
    let manifest = generate_manifest(&config)?;
    // ...
}
```

## Candid → JSON Schema Mapping

| Candid Type | JSON Schema |
|---|---|
| `nat` | `{ "type": "string", "pattern": "^[0-9]+$" }` |
| `int` | `{ "type": "string", "pattern": "^-?[0-9]+$" }` |
| `nat8/16/32` | `{ "type": "integer", "minimum": 0, "maximum": N }` |
| `nat64` | `{ "type": "string", "pattern": "^[0-9]+$" }` |
| `text` | `{ "type": "string" }` |
| `bool` | `{ "type": "boolean" }` |
| `blob` | `{ "type": "string", "contentEncoding": "base64" }` |
| `principal` | `{ "type": "string", "pattern": "^[a-z0-9-]+..." }` |
| `opt T` | `{ "oneOf": [schema(T), { "type": "null" }] }` |
| `vec T` | `{ "type": "array", "items": schema(T) }` |
| `record { a: T }` | `{ "type": "object", "properties": { "a": schema(T) } }` |
| `variant { A; B: T }` | `{ "oneOf": [{ "const": "A" }, { "type": "object", "properties": { "B": schema(T) } }] }` |

Recursive types (e.g., `type Value = variant { Array: vec Value }`) emit `{ "description": "Recursive type: Value" }` at the recursion point to avoid infinite expansion.

## Testing

```bash
cargo test -p ic-webmcp-codegen
```

## Related

- [`ic-webmcp-asset-middleware`](../asset-middleware) — Rust helpers for serving the manifest from a canister with correct CORS headers
- [`@dfinity/webmcp`](../../../packages/ic-webmcp) — TypeScript browser library
- [WebMCP Specification](https://webmcp.link/)
