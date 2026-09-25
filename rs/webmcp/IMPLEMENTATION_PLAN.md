# WebMCP for the Internet Computer — Implementation Plan

## Overview

WebMCP (Web Model Context Protocol) is a W3C standard that lets websites expose structured, callable tools to AI agents via browser APIs. The IC is uniquely suited for WebMCP because Candid interfaces already define structured tool schemas, certified queries provide verifiable responses, and Internet Identity enables scoped agent authentication.

This plan covers building **4 deliverables**:

1. **`ic-webmcp-codegen`** — Rust build tool: `.did` → `webmcp.json` + `webmcp.js`
2. **`@dfinity/webmcp`** — TypeScript npm package: bridge `navigator.modelContext` ↔ `@dfinity/agent`
3. **Asset canister middleware** — Auto-serve `/.well-known/webmcp.json`
4. **`dfx` integration** — Config in `dfx.json`, auto-generation on build

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  AI Agent (Chrome 146+ with WebMCP)             │
│  ┌───────────────────────────────────────────┐  │
│  │ navigator.modelContext                     │  │
│  │   → discovers tools from webmcp.json      │  │
│  │   → calls execute() with typed params     │  │
│  └───────────────┬───────────────────────────┘  │
└──────────────────┼──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  @dfinity/webmcp (browser JS)                   │
│  ┌───────────────────────────────────────────┐  │
│  │ 1. Fetches /.well-known/webmcp.json       │  │
│  │ 2. Registers tools via navigator API      │  │
│  │ 3. Maps execute() → agent.call/query()    │  │
│  │ 4. Handles II delegation for auth         │  │
│  │ 5. Returns certified responses w/ proofs  │  │
│  └───────────────┬───────────────────────────┘  │
└──────────────────┼──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  IC Boundary Node (HTTP Gateway)                │
│  HTTP POST → Canister update/query call         │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  Backend Canister                               │
│  ┌───────────────────────────────────────────┐  │
│  │ Candid interface (.did)                   │  │
│  │   service : {                             │  │
│  │     transfer : (TransferArg) → (Result);  │  │
│  │     balance_of : (Account) → (nat) query; │  │
│  │   }                                       │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Asset canister serves:                    │  │
│  │   /.well-known/webmcp.json (manifest)     │  │
│  │   /webmcp.js (registration script)        │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Deliverable 1: `ic-webmcp-codegen` (Rust)

**Location**: `rs/webmcp/codegen/`

### Purpose
Parse `.did` files and generate:
- `webmcp.json` — tool manifest for discovery
- `webmcp.js` — browser script that registers tools via `navigator.modelContext`

### Key Files

```
rs/webmcp/codegen/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── did_parser.rs       # Parse .did → internal representation
│   ├── schema_mapper.rs    # Candid types → JSON Schema
│   ├── manifest.rs         # Generate webmcp.json
│   ├── js_emitter.rs       # Generate webmcp.js
│   └── config.rs           # Read webmcp config from dfx.json
└── tests/
    ├── icrc1_ledger.did     # Test fixture
    └── codegen_tests.rs
```

### Candid → JSON Schema Mapping

| Candid Type | JSON Schema |
|---|---|
| `nat` | `{ "type": "string", "pattern": "^[0-9]+$" }` |
| `int` | `{ "type": "string", "pattern": "^-?[0-9]+$" }` |
| `nat8/16/32` | `{ "type": "integer", "minimum": 0 }` |
| `text` | `{ "type": "string" }` |
| `bool` | `{ "type": "boolean" }` |
| `blob` | `{ "type": "string", "contentEncoding": "base64" }` |
| `principal` | `{ "type": "string", "pattern": "^[a-z0-9-]+$" }` |
| `opt T` | `{ "oneOf": [schema(T), { "type": "null" }] }` |
| `vec T` | `{ "type": "array", "items": schema(T) }` |
| `record { a: T; b: U }` | `{ "type": "object", "properties": { "a": schema(T), "b": schema(U) } }` |
| `variant { A; B: T }` | `{ "oneOf": [{ "const": "A" }, { "type": "object", "properties": { "B": schema(T) } }] }` |

### Generated `webmcp.json` Format

```json
{
  "schema_version": "1.0",
  "canister": {
    "id": "ryjl3-tyaaa-aaaaa-aaaba-cai",
    "name": "ICP Ledger",
    "description": "ICP token ledger implementing ICRC-1/2/3"
  },
  "tools": [
    {
      "name": "icrc1_balance_of",
      "description": "Get the token balance of an account",
      "canister_method": "icrc1_balance_of",
      "method_type": "query",
      "certified": true,
      "inputSchema": {
        "type": "object",
        "properties": {
          "owner": { "type": "string", "description": "Principal ID" },
          "subaccount": { "type": ["string", "null"], "contentEncoding": "base64" }
        },
        "required": ["owner"]
      },
      "outputSchema": {
        "type": "string",
        "description": "Balance in e8s",
        "pattern": "^[0-9]+$"
      }
    },
    {
      "name": "icrc1_transfer",
      "description": "Transfer tokens to another account",
      "canister_method": "icrc1_transfer",
      "method_type": "update",
      "requires_auth": true,
      "inputSchema": {
        "type": "object",
        "properties": {
          "to": {
            "type": "object",
            "properties": {
              "owner": { "type": "string" },
              "subaccount": { "type": ["string", "null"] }
            },
            "required": ["owner"]
          },
          "amount": { "type": "string", "pattern": "^[0-9]+$" },
          "memo": { "type": ["string", "null"], "contentEncoding": "base64" },
          "fee": { "type": ["string", "null"] },
          "created_at_time": { "type": ["integer", "null"] }
        },
        "required": ["to", "amount"]
      }
    }
  ],
  "authentication": {
    "type": "internet-identity",
    "delegation_targets": ["ryjl3-tyaaa-aaaaa-aaaba-cai"],
    "recommended_scope": {
      "icrc1_transfer": {
        "max_ttl_seconds": 3600,
        "description": "Authorize agent to transfer tokens on your behalf"
      }
    }
  }
}
```

### Generated `webmcp.js` Skeleton

```javascript
import { ICWebMCP } from '@dfinity/webmcp';

const webmcp = new ICWebMCP({
  manifestUrl: '/.well-known/webmcp.json',
  // Auto-detected from manifest, but overridable:
  // canisterId: 'ryjl3-tyaaa-aaaaa-aaaba-cai',
  // host: 'https://icp-api.io',
});

// Auto-registers all tools from manifest
await webmcp.registerAll();
```

---

## Deliverable 2: `@dfinity/webmcp` (TypeScript)

**Location**: `packages/ic-webmcp/`

### Purpose
Browser-side library that:
1. Fetches `webmcp.json` manifest
2. Creates `@dfinity/agent` instances
3. Registers tools with `navigator.modelContext`
4. Maps tool calls → canister calls
5. Handles Internet Identity delegation
6. Wraps certified query responses with proofs

### Key Files

```
packages/ic-webmcp/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts                # Main exports
│   ├── ic-webmcp.ts            # Core ICWebMCP class
│   ├── manifest.ts             # Fetch & parse webmcp.json
│   ├── tool-registry.ts        # Register tools with navigator.modelContext
│   ├── agent-bridge.ts         # Map tool execute() → agent.call/query
│   ├── auth.ts                 # Internet Identity scoped delegation
│   ├── certified-response.ts   # Wrap certified query proofs
│   ├── candid-json.ts          # Convert JSON params ↔ Candid values
│   └── types.ts                # TypeScript interfaces
├── tests/
│   ├── manifest.test.ts
│   ├── tool-registry.test.ts
│   ├── agent-bridge.test.ts
│   └── candid-json.test.ts
└── README.md
```

### Core Class API

```typescript
interface ICWebMCPConfig {
  manifestUrl?: string;        // default: '/.well-known/webmcp.json'
  canisterId?: string;         // override from manifest
  host?: string;               // default: 'https://icp-api.io'
  identity?: Identity;         // pre-existing identity
  onAuthRequired?: () => Promise<Identity>;  // callback for II login
}

class ICWebMCP {
  constructor(config: ICWebMCPConfig);

  // Fetch manifest and register all tools
  async registerAll(): Promise<void>;

  // Register a single tool by name
  async registerTool(toolName: string): Promise<void>;

  // Unregister all tools (cleanup)
  async unregisterAll(): Promise<void>;

  // Get the underlying agent
  getAgent(): HttpAgent;

  // Set identity (after II login)
  setIdentity(identity: Identity): void;

  // Create scoped delegation for agent auth
  async createAgentDelegation(opts: {
    methods?: string[];
    maxTtlSeconds?: number;
    constraints?: Record<string, unknown>;
  }): Promise<DelegationIdentity>;
}
```

### Tool Registration Flow

```typescript
// Inside tool-registry.ts
async function registerCanisterTool(
  tool: WebMCPToolDefinition,
  agent: HttpAgent,
  canisterId: Principal,
) {
  const { name, description, inputSchema, canister_method, method_type } = tool;

  navigator.modelContext.registerTool({
    name,
    description,
    inputSchema,
    execute: async (params: Record<string, unknown>) => {
      // Convert JSON params to Candid
      const candidArgs = jsonToCandid(params, tool.candidTypes);

      if (method_type === 'query') {
        const result = await agent.query(canisterId, {
          methodName: canister_method,
          arg: candidArgs,
        });
        return candidToJson(result);
      } else {
        // Check auth
        if (tool.requires_auth && agent.isAnonymous()) {
          throw new Error(`Tool "${name}" requires authentication. Please connect Internet Identity.`);
        }
        const result = await agent.call(canisterId, {
          methodName: canister_method,
          arg: candidArgs,
        });
        return candidToJson(result);
      }
    },
  });
}
```

### Certified Response Wrapper

```typescript
// Inside certified-response.ts
interface CertifiedToolResponse<T> {
  value: T;
  certified: true;
  certificate: ArrayBuffer;    // BLS threshold signature
  tree: ArrayBuffer;           // Merkle witness
  timestamp_nanos: bigint;
  subnet_id: string;
  // Human-readable verification status
  verification: 'verified' | 'unverified';
}

async function executeCertifiedQuery(
  agent: HttpAgent,
  canisterId: Principal,
  method: string,
  args: ArrayBuffer,
): Promise<CertifiedToolResponse<unknown>> {
  const response = await agent.readState(canisterId, {
    paths: [/* request_status path */],
  });

  // Verify certificate against IC root key
  const verified = await verifyCertificate(response.certificate);

  return {
    value: candidToJson(response.reply.arg),
    certified: true,
    certificate: response.certificate,
    tree: response.tree,
    timestamp_nanos: response.timestamp,
    subnet_id: response.subnetId,
    verification: verified ? 'verified' : 'unverified',
  };
}
```

---

## Deliverable 3: Asset Canister Middleware

**Location**: `rs/webmcp/asset-middleware/`

### Purpose
Extend the IC asset canister to auto-serve WebMCP manifest at `/.well-known/webmcp.json`.

### Approach
Add an optional `webmcp` section to asset canister configuration. When present:
- Serve `/.well-known/webmcp.json` with correct CORS headers
- Inject `<script src="/webmcp.js">` into HTML responses (opt-in)
- Support `Content-Type: application/json` with `Access-Control-Allow-Origin: *` for agent discovery

### CORS Headers for Tool Discovery

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: Content-Type
Content-Type: application/json
```

---

## Deliverable 4: `dfx` Integration

### `dfx.json` Configuration

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
          "add_to_cart.quantity": "Number of items to add (default 1)",
          "checkout.payment_method": "Payment method: 'icp' or 'cycles'"
        }
      }
    },
    "frontend": {
      "type": "assets",
      "dependencies": ["backend"],
      "webmcp": {
        "inject_script": true,
        "serve_manifest": true
      }
    }
  }
}
```

### Build Pipeline

`dfx build` with webmcp enabled:

1. Parse `backend.did`
2. Filter to `expose_methods`
3. Map Candid types → JSON Schema
4. Merge `descriptions` and `param_descriptions`
5. Generate `webmcp.json` manifest
6. Generate `webmcp.js` registration script
7. Copy both to frontend asset canister's assets
8. Configure `/.well-known/webmcp.json` route

---

## Implementation Order

### Phase 1: Core Codegen (Week 1-2)
1. `rs/webmcp/codegen/src/did_parser.rs` — Parse .did files using `candid_parser`
2. `rs/webmcp/codegen/src/schema_mapper.rs` — Candid → JSON Schema
3. `rs/webmcp/codegen/src/manifest.rs` — Generate webmcp.json
4. `rs/webmcp/codegen/src/config.rs` — Read config from dfx.json
5. Tests with ICRC-1 ledger .did as fixture

### Phase 2: TypeScript Package (Week 2-3)
1. `packages/ic-webmcp/src/manifest.ts` — Fetch & parse
2. `packages/ic-webmcp/src/candid-json.ts` — JSON ↔ Candid conversion
3. `packages/ic-webmcp/src/agent-bridge.ts` — Tool execute → canister call
4. `packages/ic-webmcp/src/tool-registry.ts` — navigator.modelContext registration
5. `packages/ic-webmcp/src/ic-webmcp.ts` — Main class tying it together
6. `packages/ic-webmcp/src/auth.ts` — II delegation support
7. `packages/ic-webmcp/src/certified-response.ts` — Certified query wrapper

### Phase 3: Integration (Week 3-4)
1. Asset canister middleware for serving manifest
2. `dfx.json` config parsing
3. End-to-end demo: ICRC-1 ledger exposed via WebMCP
4. Documentation

### Phase 4: Demo & Polish (Week 4)
1. Demo dapp: simple e-commerce canister with WebMCP
2. Chrome Canary testing with real agent interaction
3. README, examples, blog post draft

---

## Testing Strategy

### Unit Tests
- Candid type → JSON Schema mapping (all type variants)
- Config parsing from dfx.json
- Manifest generation roundtrip
- JSON ↔ Candid value conversion

### Integration Tests
- Full .did → webmcp.json pipeline (ICRC-1, NNS governance, SNS)
- Tool registration in jsdom/headless environment
- Agent bridge with mock canister responses

### E2E Tests
- Deploy canister to local replica
- Serve WebMCP manifest via asset canister
- Verify tool discovery and execution via PocketIC

---

## Open Questions

1. **Polyfill strategy**: WebMCP is only in Chrome 146 Canary. Should we ship a polyfill that works with other agent frameworks (e.g., LangChain, CrewAI)?
2. **Batch operations**: Should we support multi-canister tool bundles (e.g., "swap tokens" spans DEX + ledger)?
3. **Streaming responses**: WebMCP doesn't seem to support streaming. Should certified query polling be hidden behind the execute callback?
4. **Agent identity lifecycle**: When should II delegation be prompted — on first auth-required tool call, or upfront?
5. **Canister-to-canister tools**: Should a canister be able to declare tools that internally call other canisters?
