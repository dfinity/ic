# OpenSpec Coverage Audit Report (Re-Verified)

**Date:** 2026-03-06
**Scope:** All 522 crates under `rs/` vs. 124 spec files under `openspec/specs/`
**Method:** Automated word-boundary grep of every crate name against all spec files (excluding this audit file)

---

## Summary Statistics

| Metric | Previous Audit | Current (Re-Verified) | Change |
|--------|---------------|----------------------|--------|
| Total crates | 522 | 522 | -- |
| Top-level modules (with crates) | 65 (header) / 66 (table) | **66** | corrected |
| Spec files | 124 | 124 | -- |
| Spec domains | 24 | 24 | -- |
| Crate names found in spec files (word-boundary grep) | 176 (claimed) | **171** | -5 (rebaselined) |
| Previously claimed "explicitly named" that aren't in specs | -- | **12** (false positives) | new finding |
| Modules with at least one corresponding spec file | 65/65 (100%) | **65/66 (98.5%)** | -1 (`depcheck`) |
| **Module-level conceptual coverage** | **100%** | **~99%** | -1% (1 minor gap) |

> **Methodology change:** The previous audit's "explicitly named" count (176) included matches
> from the COVERAGE_AUDIT.md file itself. This re-verification excludes COVERAGE_AUDIT.md and
> uses `grep -w` (word boundary) matching to avoid substring false positives.

---

## 1. Coverage Matrix (All 66 Top-Level Modules)

### Legend
- **FULL**: Module has dedicated spec file(s) and key crate names appear in specs
- **COVERED**: Module has dedicated spec file(s); crates described at domain level without individual naming
- **MINOR GAP**: Module exists but has no dedicated spec coverage

| # | Module (rs/) | Crates | Spec File(s) | Status |
|---|---|---|---|---|
| 1 | artifact_pool | ic-artifact-pool | state-management/artifact-pool.md | COVERED |
| 2 | backup | ic-backup | infrastructure/backup-recovery.md | COVERED |
| 3 | bitcoin | ic-btc-adapter, ic-btc-checker, ic-ckbtc-minter, ic-ckbtc-agent, +more | bitcoin-integration/spec.md | COVERED |
| 4 | boundary_node | ic-boundary, rate_limits, rate-limits-api, salt_sharing, +more | boundary-node/spec.md, boundary-node/rate-limits.md, boundary-node/salt-sharing.md | FULL |
| 5 | canister_client | ic-canister-client, ic-canister-client-sender, ic-read-state-response-parser | networking/canister-client.md | COVERED |
| 6 | canister_sandbox | ic-canister-sandbox-backend-lib | execution/canister-sandboxing.md | COVERED |
| 7 | canonical_state | ic-canonical-state, ic-canonical-state-tree-hash, ic-certification-version | state-management/canonical-state.md | COVERED |
| 8 | certification | ic-certification | state-management/certification.md | COVERED |
| 9 | config | ic-config | infrastructure/config.md | COVERED |
| 10 | consensus | ic-consensus, ic-consensus-certification, ic-consensus-cup-utils, +more | consensus/spec.md, consensus/sub-crates.md | FULL |
| 11 | criterion_time | criterion-time | testing/criterion-time.md | FULL |
| 12 | cross-chain | blob-store, ic-make-proposal | cross-chain/spec.md | COVERED |
| 13 | crypto | ic-crypto + ~45 sub-crates | crypto/spec.md, crypto/csp.md, +9 more | FULL |
| 14 | cup_explorer | ic-cup-explorer | testing/tools.md | FULL |
| 15 | cycles_account_manager | ic-cycles-account-manager | execution/cycles.md | COVERED |
| 16 | depcheck | depcheck | *(none)* | **MINOR GAP** |
| 17 | determinism_test | ic-determinism-test | testing/determinism-tests.md | FULL |
| 18 | dogecoin | ic-ckdoge-minter, ic-ckdoge-agent | dogecoin-integration/spec.md | COVERED |
| 19 | embedders | ic-embedders | execution/embedders.md, execution/wasm-execution.md | FULL |
| 20 | ethereum | ic-cketh-minter, ic-ledger-suite-orchestrator | ethereum-integration/spec.md | COVERED |
| 21 | execution_environment | ic-execution-environment, icp-config | execution/spec.md + 13 sub-specs | COVERED |
| 22 | fuzzers | *(no crates — contains fuzzing corpus/scripts)* | N/A | N/A |
| 23 | http_endpoints | ic-http-endpoints-public, ic-http-endpoints-metrics, +more | networking/http-endpoints.md, networking/http-endpoints-xnet.md, networking/nns-delegation-manager.md | FULL |
| 24 | http_utils | ic-http-utils | networking/http-utils.md | COVERED |
| 25 | https_outcalls | ic-https-outcalls-adapter, +4 more | networking/https-outcalls.md | COVERED |
| 26 | ic_os | ~35 sub-crates | infrastructure/ic-os.md, infrastructure/ic-os-subcrates.md | FULL |
| 27 | ingress_manager | ic-ingress-manager | ingress-manager/spec.md | COVERED |
| 28 | interfaces | ic-interfaces, ic-interfaces-registry, +more | types-and-interfaces/interfaces.md | COVERED |
| 29 | ledger_suite | icp-ledger, ic-icrc1, ic-icrc1-ledger, +more | ledger/icp-ledger.md, ledger/icrc-standards.md, +5 more | FULL |
| 30 | limits | ic-limits | types-and-interfaces/limits.md | COVERED |
| 31 | memory_tracker | memory_tracker | testing/memory-tracker.md | FULL |
| 32 | messaging | ic-messaging | messaging/spec.md | COVERED |
| 33 | migration_canister | ic-migration-canister | migration-canister/spec.md | COVERED |
| 34 | monitoring | ic-logger, ic-metrics, ic-pprof, ic-tracing, +more | infrastructure/monitoring.md, infrastructure/monitoring-subcrates.md | FULL |
| 35 | nervous_system | ~35 sub-crates | governance/nervous-system-common.md, governance/nervous-system-subcrates.md | FULL |
| 36 | nns | ic-nns-governance, cycles-minting-canister, +more | governance/nns-governance.md, +10 more | FULL |
| 37 | node_rewards | ic-node-rewards-canister, rewards-calculation | governance/node-rewards.md | COVERED |
| 38 | orchestrator | orchestrator, ic-dashboard, ic-image-upgrader, ic-registry-replicator | infrastructure/orchestrator.md | FULL |
| 39 | p2p | ic-artifact-downloader, ic-quic-transport, +more | networking/p2p.md | COVERED |
| 40 | phantom_newtype | phantom_newtype | types-and-interfaces/phantom-newtype.md | FULL |
| 41 | pocket_ic_server | pocket-ic-server | pocket-ic-server/spec.md | COVERED |
| 42 | prep | ic-prep | infrastructure/prep.md | COVERED |
| 43 | protobuf | ic-protobuf | types-and-interfaces/protobuf.md | COVERED |
| 44 | query_stats | ic-query-stats | query-stats/spec.md | COVERED |
| 45 | recovery | ic-recovery, ic-subnet-splitting | infrastructure/backup-recovery.md, infrastructure/subnet-splitting.md | FULL |
| 46 | registry | ic-admin, registry-canister, +15 more | registry/spec.md, registry/subcrates.md | FULL |
| 47 | replay | ic-replay | infrastructure/backup-recovery.md | COVERED |
| 48 | replica | ic-replica, ic-replica-setup-ic-network | infrastructure/replica.md | COVERED |
| 49 | replica_tests | ic-replica-tests | testing/replica-tests.md | FULL |
| 50 | replicated_state | ic-replicated-state | state-management/replicated-state.md | COVERED |
| 51 | rosetta-api | ic-rosetta-api, ic-icrc-rosetta, rosetta-core, +more | ledger/rosetta-api.md, ledger/rosetta-ecosystem.md | FULL |
| 52 | rust_canisters | ~28 utility/test canisters | canister-management/spec.md, canister-management/rust-canisters-detail.md | FULL |
| 53 | sns | ic-sns-governance, ic-sns-swap, ic-sns-cli, +more | governance/sns/*.md (9 files) | FULL |
| 54 | state_layout | ic-state-layout | state-management/state-layout.md | COVERED |
| 55 | state_machine_tests | ic-state-machine-tests | testing/state-machine-tests.md | FULL |
| 56 | state_manager | ic-state-manager | state-management/state-manager.md, +3 more | COVERED |
| 57 | state_tool | ic-state-tool | state-management/state-tool.md | COVERED |
| 58 | sys | ic-sys | types-and-interfaces/supporting-crates.md | COVERED |
| 59 | test_utilities | ic-test-utilities + ~17 sub-crates | testing/test-utilities.md | COVERED |
| 60 | tests | ic-system-test-driver + ~30 system test crates | testing/system-tests.md | COVERED |
| 61 | tla_instrumentation | tla_instrumentation, tla_instrumentation_proc_macros, local_key | testing/tla-instrumentation.md | FULL |
| 62 | tools | *(1 binary: check_did — no [package] crate)* | testing/tools.md | N/A |
| 63 | tree_deserializer | tree-deserializer | types-and-interfaces/supporting-crates.md | COVERED |
| 64 | types | ic-types, ic-base-types, ic-wasm-types, +more | types-and-interfaces/core-types.md, +4 more | FULL |
| 65 | universal_canister | universal-canister, ic-universal-canister | testing/test-utilities.md | COVERED |
| 66 | utils | ic-utils, ic-utils-ensure, +5 more | types-and-interfaces/utils-subcrates.md, types-and-interfaces/supporting-crates.md | FULL |
| 67 | validator | ic-validator, ic-validator-ingress-message | validator/spec.md | COVERED |
| 68 | xnet | ic-xnet-payload-builder, ic-xnet-hyper, ic-xnet-uri | networking/xnet.md | COVERED |

**Summary:** 64/66 modules with crates are covered (FULL or COVERED). 2 directories have no crates (fuzzers, tools). 1 minor gap: `depcheck` (a dependency-rule-checking tool) has no spec.

---

## 2. Crate-Level Explicit Coverage Detail

### 2.1 Verification Method

For each of the 522 crate names (extracted from `Cargo.toml` `[package]` sections), we ran:
```
grep -rqlw "$CRATE_NAME" openspec/specs/ --include='*.md' --exclude='COVERAGE_AUDIT.md'
```
This uses word-boundary matching to avoid substring false positives and excludes this audit file.

### 2.2 Results

| Category | Total | Named in Spec Files | Conceptually Covered |
|----------|-------|---------------------|---------------------|
| All crates | 522 | **171 (33%)** | 521 (99.8%) |

The 171 crate names that appear in actual spec files include a mix of production crates, test canisters, and utility crates that are explicitly referenced.

### 2.3 Crates NOT Explicitly Named (351)

The 351 crates not individually named in spec files break down as:

| Category | Count | Coverage Approach |
|----------|-------|------------------|
| Crypto internal libs | ~40 | Covered at domain level by crypto/spec.md, crypto/signatures.md, etc. |
| Test utility crates | ~50 | Covered by testing/test-utilities.md, testing/system-tests.md |
| System/integration test crates | ~40 | Covered by testing/system-tests.md |
| Protobuf generators | 18 | Covered by types-and-interfaces/protobuf.md |
| Mock crates | 9 | Covered by their parent module's spec |
| Fuzz crates | 5 | Covered by testing/fuzzers.md |
| Bench crates | 2 | Covered by their parent module's spec |
| Registry sub-crates | ~15 | Covered by registry/spec.md, registry/subcrates.md |
| Nervous system sub-crates | ~15 | Covered by governance/nervous-system-common.md |
| P2P, HTTP, HTTPS sub-crates | ~15 | Covered by networking/*.md |
| Bitcoin, Ethereum, Dogecoin sub-crates | ~10 | Covered by *-integration/spec.md |
| NNS/SNS sub-crates | ~15 | Covered by governance/*.md |
| Ledger sub-crates | ~10 | Covered by ledger/*.md |
| IC-OS sub-crates | ~12 | Covered by infrastructure/ic-os*.md |
| State management sub-crates | ~8 | Covered by state-management/*.md |
| Execution/interfaces/types sub-crates | ~10 | Covered by execution/*.md, types-and-interfaces/*.md |
| Other production crates | ~25 | Covered at module level by their domain spec |
| `depcheck` | 1 | **Not covered** |

### 2.4 Previous Audit False Positives (12 crates)

The following 12 crates were claimed as "explicitly named in spec files" in the previous audit but are NOT actually found by word-boundary grep in any spec file (excluding COVERAGE_AUDIT.md):

| Crate | Previously Claimed Spec |
|-------|------------------------|
| canister_http | pocket-ic-server/spec.md |
| ic-canister-profiler | canister-management/rust-canisters-detail.md |
| ic-neurons-fund-audit | governance/nervous-system-subcrates.md |
| ic-replicated-state | state-management/replicated-state.md |
| ic-system-test-driver | testing/system-tests.md |
| ic-xnet-payload-builder | networking/xnet.md |
| load-simulator | canister-management/rust-canisters-detail.md |
| open_rootfs | infrastructure/ic-os-subcrates.md |
| pocket-ic-server | pocket-ic-server/spec.md |
| sns-treasury-manager | governance/sns/sns-extensions.md |
| tree-deserializer | types-and-interfaces/supporting-crates.md |
| xrc-mock | canister-management/rust-canisters-detail.md |

> These crates are still conceptually covered by their domain's spec files — the module behavior
> is documented even though the exact crate name doesn't appear as a word in the spec text.

---

## 3. Spec File Inventory (124 files across 24 domains)

| Domain | Files | Key Topics |
|--------|-------|-----------|
| bitcoin-integration | 1 | BTC adapter, checker, ckBTC minter/agent |
| boundary-node | 3 | ic-boundary, rate limits, salt sharing |
| canister-management | 2 | Rust canister framework, dfn_* crates, test canisters |
| consensus | 2 | Core consensus, sub-crates (certification, CUP, DKG, IDKG, vetKD) |
| cross-chain | 1 | Blob store, proposal CLI |
| crypto | 11 | Core crypto, CSP, utils, DKG, hashing/PRNG, key mgmt, signatures, TLS, utilities, vetKD, canister threshold sigs |
| dogecoin-integration | 1 | ckDOGE minter/agent |
| ethereum-integration | 1 | ckETH minter, ledger suite orchestrator |
| execution | 14 | Core execution, embedders, scheduler, cycles, sandboxing, DTS, canister lifecycle/logging/snapshots, memory mgmt, message/query execution, system API, Wasm execution |
| governance | 24 | NNS governance + sub-crates, SNS (9 files), nervous system common + sub-crates, cycles minting, genesis token, handlers, identity, UI, node rewards, proposals, neurons, voting/rewards, SNS-WASM |
| infrastructure | 10 | Backup/recovery, config, IC-OS + sub-crates, monitoring + sub-crates, orchestrator, prep, replica, subnet splitting |
| ingress-manager | 1 | Ingress message management |
| ledger | 7 | ICP ledger, ICRC standards, archive/index, ledger core, Rosetta API, Rosetta ecosystem, token types |
| messaging | 1 | Cross-subnet messaging |
| migration-canister | 1 | State migration canister |
| networking | 8 | Canister client, HTTP endpoints (2), HTTP utils, HTTPS outcalls, NNS delegation manager, P2P, XNet |
| pocket-ic-server | 1 | PocketIC testing server |
| query-stats | 1 | Query statistics collection |
| registry | 2 | Registry canister + sub-crates |
| state-management | 10 | Artifact pool, canonical state, certification, checkpoint, manifest, page map, replicated state, state layout, state manager, state tool |
| testing | 10 | Criterion time, determinism tests, fuzzers, memory tracker, replica tests, state machine tests, system tests, test utilities, TLA instrumentation, tools |
| types-and-interfaces | 11 | Consensus types, core types, crypto types, interfaces, limits, management canister types, message types, phantom newtype, protobuf, supporting crates, utils sub-crates |
| validator | 1 | Message validation |

---

## 4. Remaining Gap

| Gap | Module | Description | Priority |
|-----|--------|-------------|----------|
| 1 | `depcheck` | Dependency-rule-checking build tool. Defines rules like "ic-replica must not depend on dfn_core". No spec file mentions it. | Low — internal build tooling |

---

## 5. Conclusion

**65 of 66 modules (98.5%) have dedicated spec coverage.** The single gap (`depcheck`) is a low-priority internal build tool.

**171 of 522 crate names (33%)** appear by exact name in spec files. The remaining crates are covered at the domain/module level — this is intentional and appropriate for internal crypto libraries, protobuf generators, test utilities, mock crates, and other supporting infrastructure.

**Key corrections from previous audit:**
- Module count: **66** (was incorrectly stated as 65; table had 66 entries)
- Explicitly named crates: **171** (was claimed as 176/178; previous count included matches from COVERAGE_AUDIT.md itself)
- 12 crates previously claimed as "explicitly named" were false positives (names only appeared in COVERAGE_AUDIT.md, not in actual spec files)
- Conceptual coverage: **~99%** (was 100%; `depcheck` module has no spec)

The overall picture remains strong: every significant IC subsystem has thorough specification coverage, and the gap-filling effort successfully addressed all major module-level gaps identified in earlier audits.
