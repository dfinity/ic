"""
This module declares all direct rust dependencies.

Run `./bin/bazel-pin.sh` from the top-level directory of the working tree after changing this file
to regenerate Cargo Bazel lockfiles.
"""

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config")
load("//bazel:fuzz_testing.bzl", "DEFAULT_RUSTC_FLAGS_FOR_FUZZING")

def sanitize_external_crates(sanitizers_enabled):
    FUZZING_ANNOTATION = [crate.annotation(rustc_flags = DEFAULT_RUSTC_FLAGS_FOR_FUZZING)] if sanitizers_enabled else []
    return {
        "candid": FUZZING_ANNOTATION,
        "wasmtime": FUZZING_ANNOTATION,
        "bitcoin": FUZZING_ANNOTATION,
        "bincode": FUZZING_ANNOTATION,
        "ic-stable-structures": FUZZING_ANNOTATION,
    }

ICRC_1_REV = "26a80d777e079644cd69e883e18dad1a201f5b1a"

BUILD_INFO_REV = "701a696844fba5c87df162fbbc1ccef96f27c9d7"

MANIFESTS = [
    "//:Cargo.toml",
    "//packages/ic-ledger-hash-of:Cargo.toml",
    "//packages/ic-vetkd-utils:Cargo.toml",
    "//packages/icrc-ledger-agent:Cargo.toml",
    "//packages/icrc-ledger-client-cdk:Cargo.toml",
    "//packages/icrc-ledger-client:Cargo.toml",
    "//packages/icrc-ledger-types:Cargo.toml",
    "//packages/pocket-ic:Cargo.toml",
    "//rs/artifact_manager:Cargo.toml",
    "//rs/artifact_pool:Cargo.toml",
    "//rs/async_utils:Cargo.toml",
    "//rs/backup:Cargo.toml",
    "//rs/bitcoin/adapter:Cargo.toml",
    "//rs/bitcoin/ckbtc/agent:Cargo.toml",
    "//rs/bitcoin/ckbtc/kyt:Cargo.toml",
    "//rs/bitcoin/ckbtc/minter:Cargo.toml",
    "//rs/bitcoin/client:Cargo.toml",
    "//rs/bitcoin/consensus:Cargo.toml",
    "//rs/bitcoin/mock:Cargo.toml",
    "//rs/bitcoin/service:Cargo.toml",
    "//rs/bitcoin/types/internal:Cargo.toml",
    "//rs/boundary_node/canary_proxy:Cargo.toml",
    "//rs/boundary_node/certificate_issuance/certificate_issuer:Cargo.toml",
    "//rs/boundary_node/certificate_issuance/certificate_orchestrator:Cargo.toml",
    "//rs/boundary_node/certificate_issuance/certificate_syncer:Cargo.toml",
    "//rs/boundary_node/denylist_updater:Cargo.toml",
    "//rs/boundary_node/discower_bowndary:Cargo.toml",
    "//rs/boundary_node/ic_balance_exporter:Cargo.toml",
    "//rs/boundary_node/ic_boundary:Cargo.toml",
    "//rs/boundary_node/icx_proxy:Cargo.toml",
    "//rs/boundary_node/prober:Cargo.toml",
    "//rs/boundary_node/systemd_journal_gatewayd_shim:Cargo.toml",
    "//rs/canister_client/sender:Cargo.toml",
    "//rs/canister_client:Cargo.toml",
    "//rs/canister_sandbox:Cargo.toml",
    "//rs/canonical_state/tree_hash/test_utils:Cargo.toml",
    "//rs/canonical_state/tree_hash:Cargo.toml",
    "//rs/canonical_state:Cargo.toml",
    "//rs/certification/test-utils:Cargo.toml",
    "//rs/certification:Cargo.toml",
    "//rs/config:Cargo.toml",
    "//rs/consensus/mocks:Cargo.toml",
    "//rs/consensus/utils:Cargo.toml",
    "//rs/consensus:Cargo.toml",
    "//rs/constants:Cargo.toml",
    "//rs/criterion_time:Cargo.toml",
    "//rs/cross-chain/proposal-cli:Cargo.toml",
    "//rs/crypto/ecdsa_secp256k1:Cargo.toml",
    "//rs/crypto/ecdsa_secp256r1:Cargo.toml",
    "//rs/crypto/ed25519:Cargo.toml",
    "//rs/crypto/extended_bip32:Cargo.toml",
    "//rs/crypto/for_verification_only:Cargo.toml",
    "//rs/crypto/getrandom_for_wasm:Cargo.toml",
    "//rs/crypto/iccsa:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/der_utils:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256k1:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256r1:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/ed25519:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/iccsa/test_utils:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/iccsa:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/basic_sig/rsa_pkcs1:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/bls12_381/type:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/bls12_381/vetkd:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/hmac:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/multi_sig/bls12_381:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/seed:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/sha2:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/threshold_sig/bls12_381:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/test_utils:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/threshold_sig/tecdsa:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/tls:Cargo.toml",
    "//rs/crypto/internal/crypto_lib/types:Cargo.toml",
    "//rs/crypto/internal/crypto_service_provider/protobuf_generator:Cargo.toml",
    "//rs/crypto/internal/crypto_service_provider:Cargo.toml",
    "//rs/crypto/internal/csp_test_utils:Cargo.toml",
    "//rs/crypto/internal/logmon:Cargo.toml",
    "//rs/crypto/internal/test_vectors:Cargo.toml",
    "//rs/crypto/node_key_generation:Cargo.toml",
    "//rs/crypto/node_key_validation:Cargo.toml",
    "//rs/crypto/prng:Cargo.toml",
    "//rs/crypto/secrets_containers:Cargo.toml",
    "//rs/crypto/sha2:Cargo.toml",
    "//rs/crypto/temp_crypto:Cargo.toml",
    "//rs/crypto/test_utils/canister_sigs:Cargo.toml",
    "//rs/crypto/test_utils/canister_threshold_sigs:Cargo.toml",
    "//rs/crypto/test_utils/metrics:Cargo.toml",
    "//rs/crypto/test_utils/ni-dkg:Cargo.toml",
    "//rs/crypto/test_utils/reproducible_rng:Cargo.toml",
    "//rs/crypto/test_utils/tls:Cargo.toml",
    "//rs/crypto/test_utils:Cargo.toml",
    "//rs/crypto/tls_interfaces/mocks:Cargo.toml",
    "//rs/crypto/tls_interfaces:Cargo.toml",
    "//rs/crypto/tree_hash/test_utils:Cargo.toml",
    "//rs/crypto/tree_hash:Cargo.toml",
    "//rs/crypto/utils/basic_sig:Cargo.toml",
    "//rs/crypto/utils/canister_threshold_sig:Cargo.toml",
    "//rs/crypto/utils/ni_dkg:Cargo.toml",
    "//rs/crypto/utils/threshold_sig:Cargo.toml",
    "//rs/crypto/utils/threshold_sig_der:Cargo.toml",
    "//rs/crypto/utils/tls:Cargo.toml",
    "//rs/crypto:Cargo.toml",
    "//rs/cup_explorer:Cargo.toml",
    "//rs/cycles_account_manager:Cargo.toml",
    "//rs/depcheck:Cargo.toml",
    "//rs/determinism_test:Cargo.toml",
    "//rs/drun:Cargo.toml",
    "//rs/embedders:Cargo.toml",
    "//rs/ethereum/cketh/minter:Cargo.toml",
    "//rs/ethereum/evm-rpc-client:Cargo.toml",
    "//rs/ethereum/ledger-suite-orchestrator:Cargo.toml",
    "//rs/execution_environment:Cargo.toml",
    "//rs/execution_environment:benches/lib/Cargo.toml",
    "//rs/execution_environment:tools/Cargo.toml",
    "//rs/http_endpoints/metrics:Cargo.toml",
    "//rs/http_endpoints/public:Cargo.toml",
    "//rs/http_utils:Cargo.toml",
    "//rs/https_outcalls/adapter:Cargo.toml",
    "//rs/https_outcalls/client:Cargo.toml",
    "//rs/https_outcalls/consensus:Cargo.toml",
    "//rs/https_outcalls/service:Cargo.toml",
    "//rs/ic_os/config:Cargo.toml",
    "//rs/ic_os/deterministic_ips:Cargo.toml",
    "//rs/ic_os/dflate:Cargo.toml",
    "//rs/ic_os/diroid:Cargo.toml",
    "//rs/ic_os/fstrim_tool:Cargo.toml",
    "//rs/ic_os/guestos_tool:Cargo.toml",
    "//rs/ic_os/hostos_tool:Cargo.toml",
    "//rs/ic_os/inject_files:Cargo.toml",
    "//rs/ic_os/launch-single-vm:Cargo.toml",
    "//rs/ic_os/network:Cargo.toml",
    "//rs/ic_os/nss_icos:Cargo.toml",
    "//rs/ic_os/partition_tools:Cargo.toml",
    "//rs/ic_os/setupos-disable-checks:Cargo.toml",
    "//rs/ic_os/setupos-inject-configuration:Cargo.toml",
    "//rs/ic_os/setupos_tool:Cargo.toml",
    "//rs/ic_os/utils:Cargo.toml",
    "//rs/ic_os/vsock/guest:Cargo.toml",
    "//rs/ic_os/vsock/host:Cargo.toml",
    "//rs/ic_os/vsock/vsock_lib:Cargo.toml",
    "//rs/ingress_manager:Cargo.toml",
    "//rs/interfaces/adapter_client:Cargo.toml",
    "//rs/interfaces/certified_stream_store/mocks:Cargo.toml",
    "//rs/interfaces/certified_stream_store:Cargo.toml",
    "//rs/interfaces/mocks:Cargo.toml",
    "//rs/interfaces/registry/mocks:Cargo.toml",
    "//rs/interfaces/registry:Cargo.toml",
    "//rs/interfaces/state_manager/mocks:Cargo.toml",
    "//rs/interfaces/state_manager:Cargo.toml",
    "//rs/interfaces:Cargo.toml",
    "//rs/memory_tracker:Cargo.toml",
    "//rs/messaging:Cargo.toml",
    "//rs/monitoring/adapter_metrics/client:Cargo.toml",
    "//rs/monitoring/adapter_metrics/server:Cargo.toml",
    "//rs/monitoring/adapter_metrics/service:Cargo.toml",
    "//rs/monitoring/backtrace:Cargo.toml",
    "//rs/monitoring/logger:Cargo.toml",
    "//rs/monitoring/metrics:Cargo.toml",
    "//rs/monitoring/pprof:Cargo.toml",
    "//rs/nervous_system/clients:Cargo.toml",
    "//rs/nervous_system/collections/union_multi_map:Cargo.toml",
    "//rs/nervous_system/common/build_metadata:Cargo.toml",
    "//rs/nervous_system/common/test_canister:Cargo.toml",
    "//rs/nervous_system/common/test_keys:Cargo.toml",
    "//rs/nervous_system/common/test_utils:Cargo.toml",
    "//rs/nervous_system/common:Cargo.toml",
    "//rs/nervous_system/humanize:Cargo.toml",
    "//rs/nervous_system/integration_tests:Cargo.toml",
    "//rs/nervous_system/lock:Cargo.toml",
    "//rs/nervous_system/neurons_fund/nfplot:Cargo.toml",
    "//rs/nervous_system/neurons_fund:Cargo.toml",
    "//rs/nervous_system/proto/protobuf_generator:Cargo.toml",
    "//rs/nervous_system/proto:Cargo.toml",
    "//rs/nervous_system/proxied_canister_calls_tracker:Cargo.toml",
    "//rs/nervous_system/root:Cargo.toml",
    "//rs/nervous_system/runtime:Cargo.toml",
    "//rs/nervous_system/string:Cargo.toml",
    "//rs/nervous_system/tools/sync-with-released-nevous-system-wasms:Cargo.toml",
    "//rs/nns/cmc:Cargo.toml",
    "//rs/nns/common/protobuf_generator:Cargo.toml",
    "//rs/nns/common:Cargo.toml",
    "//rs/nns/constants:Cargo.toml",
    "//rs/nns/governance/protobuf_generator:Cargo.toml",
    "//rs/nns/governance:Cargo.toml",
    "//rs/nns/gtc/protobuf_generator:Cargo.toml",
    "//rs/nns/gtc:Cargo.toml",
    "//rs/nns/gtc_accounts:Cargo.toml",
    "//rs/nns/handlers/lifeline/impl:Cargo.toml",
    "//rs/nns/handlers/lifeline/interface:Cargo.toml",
    "//rs/nns/handlers/root/impl/protobuf_generator:Cargo.toml",
    "//rs/nns/handlers/root/impl:Cargo.toml",
    "//rs/nns/handlers/root/interface:Cargo.toml",
    "//rs/nns/identity:Cargo.toml",
    "//rs/nns/init:Cargo.toml",
    "//rs/nns/inspector:Cargo.toml",
    "//rs/nns/integration_tests:Cargo.toml",
    "//rs/nns/nns-ui:Cargo.toml",
    "//rs/nns/sns-wasm/protobuf_generator:Cargo.toml",
    "//rs/nns/sns-wasm:Cargo.toml",
    "//rs/nns/test_utils/golden_nns_state:Cargo.toml",
    "//rs/nns/test_utils:Cargo.toml",
    "//rs/nns/test_utils_macros:Cargo.toml",
    "//rs/orchestrator/dashboard:Cargo.toml",
    "//rs/orchestrator/registry_replicator:Cargo.toml",
    "//rs/orchestrator:Cargo.toml",
    "//rs/p2p/consensus_manager:Cargo.toml",
    "//rs/p2p/memory_transport:Cargo.toml",
    "//rs/p2p/peer_manager:Cargo.toml",
    "//rs/p2p/quic_transport:Cargo.toml",
    "//rs/p2p/state_sync_manager:Cargo.toml",
    "//rs/p2p/test_utils:Cargo.toml",
    "//rs/phantom_newtype:Cargo.toml",
    "//rs/pocket_ic_server:Cargo.toml",
    "//rs/prep:Cargo.toml",
    "//rs/protobuf/generator:Cargo.toml",
    "//rs/protobuf:Cargo.toml",
    "//rs/recovery/subnet_splitting:Cargo.toml",
    "//rs/recovery:Cargo.toml",
    "//rs/registry/admin-derive:Cargo.toml",
    "//rs/registry/admin:Cargo.toml",
    "//rs/registry/canister/protobuf_generator:Cargo.toml",
    "//rs/registry/canister:Cargo.toml",
    "//rs/registry/client:Cargo.toml",
    "//rs/registry/fake:Cargo.toml",
    "//rs/registry/helpers:Cargo.toml",
    "//rs/registry/keys:Cargo.toml",
    "//rs/registry/local_registry:Cargo.toml",
    "//rs/registry/local_store/artifacts:Cargo.toml",
    "//rs/registry/local_store:Cargo.toml",
    "//rs/registry/nns_data_provider:Cargo.toml",
    "//rs/registry/nns_data_provider_wrappers:Cargo.toml",
    "//rs/registry/proto/generator:Cargo.toml",
    "//rs/registry/proto:Cargo.toml",
    "//rs/registry/proto_data_provider:Cargo.toml",
    "//rs/registry/provisional_whitelist:Cargo.toml",
    "//rs/registry/regedit:Cargo.toml",
    "//rs/registry/routing_table:Cargo.toml",
    "//rs/registry/subnet_features:Cargo.toml",
    "//rs/registry/subnet_type:Cargo.toml",
    "//rs/registry/transport/protobuf_generator:Cargo.toml",
    "//rs/registry/transport:Cargo.toml",
    "//rs/replay:Cargo.toml",
    "//rs/replica/setup_ic_network:Cargo.toml",
    "//rs/replica:Cargo.toml",
    "//rs/replica_tests:Cargo.toml",
    "//rs/replicated_state:Cargo.toml",
    "//rs/rosetta-api/hardware_wallet_tests:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/archive:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/index:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/ledger:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/protobuf_generator:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/rosetta-integration-tests:Cargo.toml",
    "//rs/rosetta-api/icp_ledger/test_utils:Cargo.toml",
    "//rs/rosetta-api/icp_ledger:Cargo.toml",
    "//rs/rosetta-api/icrc1/archive:Cargo.toml",
    "//rs/rosetta-api/icrc1/benchmark/generator:Cargo.toml",
    "//rs/rosetta-api/icrc1/benchmark/worker:Cargo.toml",
    "//rs/rosetta-api/icrc1/index-ng:Cargo.toml",
    "//rs/rosetta-api/icrc1/index:Cargo.toml",
    "//rs/rosetta-api/icrc1/ledger/sm-tests:Cargo.toml",
    "//rs/rosetta-api/icrc1/ledger:Cargo.toml",
    "//rs/rosetta-api/icrc1/rosetta/client:Cargo.toml",
    "//rs/rosetta-api/icrc1/rosetta/runner:Cargo.toml",
    "//rs/rosetta-api/icrc1/rosetta:Cargo.toml",
    "//rs/rosetta-api/icrc1/test_utils:Cargo.toml",
    "//rs/rosetta-api/icrc1/tokens_u256:Cargo.toml",
    "//rs/rosetta-api/icrc1/tokens_u64:Cargo.toml",
    "//rs/rosetta-api/icrc1:Cargo.toml",
    "//rs/rosetta-api/ledger_canister_blocks_synchronizer/test_utils:Cargo.toml",
    "//rs/rosetta-api/ledger_canister_blocks_synchronizer:Cargo.toml",
    "//rs/rosetta-api/ledger_canister_core:Cargo.toml",
    "//rs/rosetta-api/ledger_core:Cargo.toml",
    "//rs/rosetta-api/rosetta_core:Cargo.toml",
    "//rs/rosetta-api/test_utils:Cargo.toml",
    "//rs/rosetta-api/tvl/xrc_mock:Cargo.toml",
    "//rs/rosetta-api/tvl:Cargo.toml",
    "//rs/rosetta-api:Cargo.toml",
    "//rs/rust_canisters/call_tree_test:Cargo.toml",
    "//rs/rust_canisters/canister_creator:Cargo.toml",
    "//rs/rust_canisters/canister_log:Cargo.toml",
    "//rs/rust_canisters/canister_serve:Cargo.toml",
    "//rs/rust_canisters/canister_test:Cargo.toml",
    "//rs/rust_canisters/dfn_candid:Cargo.toml",
    "//rs/rust_canisters/dfn_core:Cargo.toml",
    "//rs/rust_canisters/dfn_http:Cargo.toml",
    "//rs/rust_canisters/dfn_http_metrics:Cargo.toml",
    "//rs/rust_canisters/dfn_json:Cargo.toml",
    "//rs/rust_canisters/dfn_macro:Cargo.toml",
    "//rs/rust_canisters/dfn_protobuf:Cargo.toml",
    "//rs/rust_canisters/downstream_calls_test:Cargo.toml",
    "//rs/rust_canisters/ecdsa:Cargo.toml",
    "//rs/rust_canisters/http_types:Cargo.toml",
    "//rs/rust_canisters/memory_test:Cargo.toml",
    "//rs/rust_canisters/on_wire:Cargo.toml",
    "//rs/rust_canisters/pmap:Cargo.toml",
    "//rs/rust_canisters/proxy_canister:Cargo.toml",
    "//rs/rust_canisters/response_payload_test:Cargo.toml",
    "//rs/rust_canisters/stable_reader:Cargo.toml",
    "//rs/rust_canisters/stable_structures:Cargo.toml",
    "//rs/rust_canisters/statesync_test:Cargo.toml",
    "//rs/rust_canisters/tests:Cargo.toml",
    "//rs/rust_canisters/xnet_test:Cargo.toml",
    "//rs/scenario_tests:Cargo.toml",
    "//rs/sns/audit:Cargo.toml",
    "//rs/sns/cli:Cargo.toml",
    "//rs/sns/governance/proposal_criticality:Cargo.toml",
    "//rs/sns/governance/proposals_amount_total_limit:Cargo.toml",
    "//rs/sns/governance/protobuf_generator:Cargo.toml",
    "//rs/sns/governance/token_valuation:Cargo.toml",
    "//rs/sns/governance:Cargo.toml",
    "//rs/sns/init/protobuf_generator:Cargo.toml",
    "//rs/sns/init:Cargo.toml",
    "//rs/sns/integration_tests:Cargo.toml",
    "//rs/sns/root/protobuf_generator:Cargo.toml",
    "//rs/sns/root:Cargo.toml",
    "//rs/sns/swap/proto_library:Cargo.toml",
    "//rs/sns/swap:Cargo.toml",
    "//rs/sns/test_utils:Cargo.toml",
    "//rs/starter:Cargo.toml",
    "//rs/state_layout:Cargo.toml",
    "//rs/state_machine_tests:Cargo.toml",
    "//rs/state_manager:Cargo.toml",
    "//rs/state_tool:Cargo.toml",
    "//rs/sys:Cargo.toml",
    "//rs/system_api:Cargo.toml",
    "//rs/test_utilities/artifact_pool:Cargo.toml",
    "//rs/test_utilities/compare_dirs:Cargo.toml",
    "//rs/test_utilities/consensus:Cargo.toml",
    "//rs/test_utilities/execution_environment:Cargo.toml",
    "//rs/test_utilities/load_wasm:Cargo.toml",
    "//rs/test_utilities/logger:Cargo.toml",
    "//rs/test_utilities/metrics:Cargo.toml",
    "//rs/test_utilities/serialization:Cargo.toml",
    "//rs/test_utilities/state:Cargo.toml",
    "//rs/test_utilities/time:Cargo.toml",
    "//rs/test_utilities/tmpdir:Cargo.toml",
    "//rs/test_utilities/types:Cargo.toml",
    "//rs/test_utilities:Cargo.toml",
    "//rs/tests/httpbin-rs:Cargo.toml",
    "//rs/tests/nested:Cargo.toml",
    "//rs/tests/networking/canister_http:Cargo.toml",
    "//rs/tests/nns/ic_mainnet_nns_recovery:Cargo.toml",
    "//rs/tests/nns/sns:Cargo.toml",
    "//rs/tests/sdk:Cargo.toml",
    "//rs/tests/test_canisters/http_counter:Cargo.toml",
    "//rs/tests/test_canisters/kv_store:Cargo.toml",
    "//rs/tests/test_canisters/message:Cargo.toml",
    "//rs/tests/testing_verification/spec_compliance:Cargo.toml",
    "//rs/tests/testing_verification/testnets:Cargo.toml",
    "//rs/tests/testing_verification/wabt-tests:Cargo.toml",
    "//rs/tests/testing_verification:Cargo.toml",
    "//rs/tests:Cargo.toml",
    "//rs/tree_deserializer:Cargo.toml",
    "//rs/types/base_types/protobuf_generator:Cargo.toml",
    "//rs/types/base_types:Cargo.toml",
    "//rs/types/error_types:Cargo.toml",
    "//rs/types/management_canister_types:Cargo.toml",
    "//rs/types/types:Cargo.toml",
    "//rs/types/types_test_utils:Cargo.toml",
    "//rs/types/wasm_types:Cargo.toml",
    "//rs/universal_canister/lib:Cargo.toml",
    "//rs/utils/ensure:Cargo.toml",
    "//rs/utils/lru_cache:Cargo.toml",
    "//rs/utils/rustfmt:Cargo.toml",
    "//rs/utils:Cargo.toml",
    "//rs/validator/ingress_message/test_canister:Cargo.toml",
    "//rs/validator/ingress_message:Cargo.toml",
    "//rs/validator:Cargo.toml",
    "//rs/workload_generator:Cargo.toml",
    "//rs/xnet/endpoint:Cargo.toml",
    "//rs/xnet/hyper:Cargo.toml",
    "//rs/xnet/payload_builder:Cargo.toml",
    "//rs/xnet/uri:Cargo.toml",
]

def foo(name, actual, tags):
    if name == "axum-0.7.4":
        return native.alias(name = "axum", actual = actual, tags = tags)
    if name == "bs58-0.5.0":
        return native.alias(name = "bs58", actual = actual, tags = tags)
    if name == "clap-4.4.8":
        return native.alias(name = "clap", actual = actual, tags = tags)
    if name == "http-1.1.0":
        return native.alias(name = "http", actual = actual, tags = tags)
    if name == "http-body-1.0.0":
        return native.alias(name = "http-body", actual = actual, tags = tags)
    if name == "hyper-1.3.1":
        return native.alias(name = "hyper", actual = actual, tags = tags)
    if name == "hyper-rustls-0.24.2":
        return native.alias(name = "hyper-rustls", actual = actual, tags = tags)
    if name == "ic0-0.21.1":
        return native.alias(name = "ic0", actual = actual, tags = tags)
    if name == "opentelemetry-0.23.0":
        return native.alias(name = "opentelemetry", actual = actual, tags = tags)
    if name == "opentelemetry-prometheus-0.16.0":
        return native.alias(name = "opentelemetry-prometheus", actual = actual, tags = tags)
    if name == "reqwest-0.12.4":
        return native.alias(name = "reqwest", actual = actual, tags = tags)
    if name == "ring-0.17.7":
        return native.alias(name = "ring", actual = actual, tags = tags)
    if name == "rustls-0.23.8":
        return native.alias(name = "rustls", actual = actual, tags = tags)
    if name == "sha2-0.10.8":
        return native.alias(name = "sha2", actual = actual, tags = tags)
    if name == "tokio-rustls-0.26.0":
        return native.alias(name = "tokio-rustls", actual = actual, tags = tags)
    if name == "tower-http-0.5.2":
        return native.alias(name = "tower-http", actual = actual, tags = tags)
    if name == "wasmparser-0.201.0":
        return native.alias(name = "wasmparser", actual = actual, tags = tags)
    else:
        return native.alias(name = name, actual = actual, tags = tags)


# TODO: for each crate here (axum, bs58, clap) add an alias_rule
# TODO: dedup this from the above, this is stupid
# TODO: figure out how to find duplicates even if they're not defined here (but
#   only defined in manifests)
def external_crates_repository(name, cargo_lockfile, lockfile, sanitizers_enabled):
    CRATE_ANNOTATIONS = {
        "axum": [crate.annotation(
            version = "0.7.4",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "bs58": [crate.annotation(
            version = "0.5.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "clap": [crate.annotation(
            version = "4.4.8",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "http": [crate.annotation(
            version = "1.1.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "http-body": [crate.annotation(
            version = "1.0.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "hyper": [crate.annotation(
            version = "1.3.1",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "hyper-rustls": [crate.annotation(
            version = "0.24.2",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "ic0": [crate.annotation(
            version = "0.21.1",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "opentelemetry": [crate.annotation(
            version = "0.23.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "opentelemetry-prometheus": [crate.annotation(
            version = "0.16.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "reqwest": [crate.annotation(
            version = "0.12.4",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "rustls": [crate.annotation(
            version = "0.23.8",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "sha2": [crate.annotation(
            version = "0.10.8",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "tokio-rustls": [crate.annotation(
            version = "0.26.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "tower-http": [crate.annotation(
            version = "0.5.2",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "wasmparser": [crate.annotation(
            version = "0.201.0",
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "canbench": [crate.annotation(
            gen_binaries = True,
        )],
        "ic_bls12_381": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "k256": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "p256": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "ring": [crate.annotation(
            build_script_env = {
                "CFLAGS": "-fdebug-prefix-map=$${pwd}=/source",
            },
            alias_rule = "@@ic//bazel:external_crates.bzl:foo",
        )],
        "ic-wasm": [crate.annotation(
            gen_binaries = True,
        )],
        "librocksdb-sys": [crate.annotation(
            build_script_env = {
                # Bazel executors assign only one core when executing
                # the build script, making rocksdb compilation
                # extremely slow. Bazel doesn't provide any way to
                # override this settings so we cheat by starting more
                # processes in parallel.
                #
                # See IDX-2406.
                "NUM_JOBS": "8",
            },
        )],
        "pprof": [crate.annotation(
            build_script_data = [
                "@com_google_protobuf//:protoc",
            ],
            build_script_env = {
                "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
            },
        )],
        "prost-build": [crate.annotation(
            build_script_env = {
                "PROTOC_NO_VENDOR": "1",
            },
        )],
        "metrics-proxy": [crate.annotation(
            gen_binaries = True,
        )],
    }
    CRATE_ANNOTATIONS.update(sanitize_external_crates(sanitizers_enabled = sanitizers_enabled))
    crates_repository(
        name = name,
        isolated = True,
        cargo_lockfile = cargo_lockfile,
        lockfile = lockfile,
        cargo_config = "//:bazel/cargo.config",
        annotations = CRATE_ANNOTATIONS,
        manifests = MANIFESTS,
        packages = {
            "actix-rt": crate.spec(
                version = "^2.2.0",
            ),
            "actix-web": crate.spec(
                version = "^4.3.0",
            ),
            "addr": crate.spec(
                version = "^0.15.6",
                default_features = False,
                features = [
                    "idna",
                ],
            ),
            "aide": crate.spec(
                version = "^0.13.0",
                features = [
                    "axum",
                ],
            ),
            "arbitrary": crate.spec(
                version = "^1.3.0",
            ),
            "arc-swap": crate.spec(
                version = "^1",
            ),
            "anyhow": crate.spec(
                version = "^1",
            ),
            "arrayvec": crate.spec(
                version = "^0.7.4",
            ),
            "askama": crate.spec(
                version = "^0.12.1",
                features = [
                    "serde-json",
                ],
            ),
            "assert-json-diff": crate.spec(
                version = "^2.0.1",
            ),
            "assert_cmd": crate.spec(
                version = "^2.0.12",
            ),
            "assert_matches": crate.spec(
                version = "^1.5.0",
            ),
            "async-recursion": crate.spec(
                version = "^1.0.5",
            ),
            "async-scoped": crate.spec(
                version = "^0.8.0",
                features = [
                    "use-tokio",
                ],
            ),
            "async-socks5": crate.spec(
                version = "^0.5.1",
            ),
            "async-stream": crate.spec(
                version = "^0.3.5",
            ),
            "async-trait": crate.spec(
                version = "^0.1.73",
            ),
            "axum_0_6_1": crate.spec(
                package = "axum",
                version = "^0.6.1",
                features = [
                    "headers",
                ],
            ),
            "axum": crate.spec(
                version = "^0.7.4",
            ),
            "axum-extra": crate.spec(
                version = "^0.9.0",
                features = ["typed-header"],
            ),
            "axum-server": crate.spec(
                version = "^0.5.1",
                features = [
                    "tls-rustls",
                ],
            ),
            "backoff": crate.spec(
                version = "^0.4.0",
            ),
            "backon": crate.spec(
                version = "^0.4.1",
            ),
            "base32": crate.spec(
                version = "^0.4.0",
            ),
            "base64": crate.spec(
                version = "^0.13.1",
            ),
            "bech32": crate.spec(
                version = "^0.9.0",
            ),
            "bincode": crate.spec(
                version = "^1.3.3",
            ),
            "bindgen": crate.spec(
                version = "^0.65.1",
                default_features = False,
                features = ["runtime"],
            ),
            "bip32": crate.spec(
                version = "^0.5.0",
                features = [
                    "secp256k1",
                ],
            ),
            "bit-vec": crate.spec(
                version = "^0.6.3",
            ),
            "bitcoin": crate.spec(
                version = "^0.28.1",
                features = [
                    "default",
                    "rand",
                    "use-serde",
                ],
            ),
            "bitcoincore-rpc": crate.spec(
                version = "^0.15.0",
            ),
            "bitcoind": crate.spec(
                version = "^0.32.0",
            ),
            "bitflags": crate.spec(
                version = "^1.2.1",
            ),
            "bs58": crate.spec(
                version = "^0.5.0",
            ),
            "ic_bls12_381": crate.spec(
                version = "^0.8.0",
                features = [
                    "alloc",
                    "experimental",
                    "groups",
                    "pairings",
                    "zeroize",
                ],
                default_features = False,
            ),
            "build-info": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = BUILD_INFO_REV,
            ),
            "build-info-build": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = BUILD_INFO_REV,
                default_features = False,
            ),
            "by_address": crate.spec(
                version = "^1.1.0",
            ),
            "byte-unit": crate.spec(
                version = "^4.0.14",
            ),
            "byteorder": crate.spec(
                version = "^1.3.4",
            ),
            "bytes": crate.spec(
                version = "^1.6.0",
            ),
            "cached": crate.spec(
                version = "^0.49",
                default_features = False,
            ),
            "canbench": crate.spec(
                version = "^0.1.4",
            ),
            "canbench-rs": crate.spec(
                version = "^0.1.4",
            ),
            "candid": crate.spec(
                version = "^0.10.6",
            ),
            "cargo_metadata": crate.spec(
                version = "^0.14.2",
            ),
            "candid_parser": crate.spec(
                version = "^0.1.2",
            ),
            "cc": crate.spec(
                version = "^1.0",
            ),
            "cddl": crate.spec(
                version = "^0.9.4",
            ),
            "cfg-if": crate.spec(version = "^1.0.0"),
            "chacha20poly1305": crate.spec(
                version = "^0.10.0",
            ),
            "chrono": crate.spec(
                version = "^0.4.38",
                default_features = False,
                features = [
                    "alloc",
                    "clock",
                    "serde",
                ],
            ),
            "ciborium": crate.spec(
                version = "^0.2.1",
            ),
            "cidr": crate.spec(
                version = "^0.2.2",
            ),
            "clap_3_2_25": crate.spec(
                package = "clap",
                version = "^3.2.25",
                features = [
                    "derive",
                ],
            ),
            "clap": crate.spec(
                version = "^4.0.0",
                features = [
                    "derive",
                    "string",
                ],
            ),
            "cloudflare": crate.spec(
                git = "https://github.com/blind-oracle/cloudflare-rs.git",
                rev = "386c8c6a0a95ad0c8a87aa1aac27b26a6cfec5cc",
                default_features = False,
                features = [
                    "rustls-tls",
                ],
            ),
            "colored": crate.spec(
                version = "^2.0.0",
            ),
            "comparable": crate.spec(
                version = "^0.5",
                features = [
                    "derive",
                ],
            ),
            "console": crate.spec(
                version = "^0.11",
            ),
            "convert_case": crate.spec(
                version = "^0.6.0",
            ),
            "crc32fast": crate.spec(
                version = "^1.2.0",
            ),
            "criterion": crate.spec(
                version = "^0.5.1",
                features = [
                    "html_reports",
                    "async_tokio",
                ],
            ),
            "crossbeam": crate.spec(
                version = "^0.8.4",
            ),
            "crossbeam-channel": crate.spec(
                version = "^0.5.11",
            ),
            "csv": crate.spec(
                version = "^1.1",
            ),
            "curve25519-dalek": crate.spec(
                version = "^4.1.3",
                features = ["group", "precomputed-tables"],
            ),
            "cvt": crate.spec(
                version = "^0.1.1",
            ),
            "dashmap": crate.spec(
                version = "^5.3.4",
            ),
            "dyn-clone": crate.spec(
                version = "^1.0.14",
            ),
            "ed25519-consensus": crate.spec(
                version = "^2.0.1",
            ),
            "ed25519-dalek": crate.spec(
                version = "^2.1.1",
                features = ["std", "zeroize", "digest", "batch", "pkcs8", "pem", "hazmat"],
            ),
            "educe": crate.spec(
                version = "^0.4",
            ),
            "either": crate.spec(
                version = "^1.6",
            ),
            "erased-serde": crate.spec(
                version = "^0.3.11",
            ),
            "escargot": crate.spec(
                version = "^0.5.7",
                features = ["print"],
            ),
            "ethabi": crate.spec(
                version = "^18.0.0",
            ),
            "ethers-core": crate.spec(
                version = "^2.0.7",
            ),
            "ethnum": crate.spec(
                version = "^1.3.2",
                features = ["serde"],
            ),
            "exec": crate.spec(
                version = "^0.3.1",
            ),
            "eyre": crate.spec(
                version = "^0.6.8",
            ),
            "ff": crate.spec(
                version = "^0.12.0",
                features = [
                    "std",
                ],
                default_features = False,
            ),
            "flate2": crate.spec(
                version = "^1.0.30",
            ),
            "form_urlencoded": crate.spec(
                version = "^1.0.0",
            ),
            "fs_extra": crate.spec(
                version = "^1.2.0",
            ),
            "futures": crate.spec(
                version = "^0.3.30",
            ),
            "futures-util": crate.spec(
                version = "^0.3.30",
            ),
            "get_if_addrs": crate.spec(
                version = "^0.5.3",
            ),
            "getrandom": crate.spec(
                version = "^0.2",
                features = [
                    "custom",
                ],
            ),
            "glob": crate.spec(
                version = "^0.3.0",
            ),
            "group": crate.spec(
                version = "^0.13",
            ),
            "hashlink": crate.spec(
                version = "^0.8.0",
            ),
            "hex": crate.spec(
                version = "^0.4.3",
                features = [
                    "serde",
                ],
            ),
            "hex-literal": crate.spec(
                version = "^0.4.1",
            ),
            "hkdf": crate.spec(
                version = "^0.12",
            ),
            "http": crate.spec(
                version = "^1.1.0",
            ),
            "http_0_2_12": crate.spec(
                package = "http",
                version = "^0.2.12",
            ),
            "http-body": crate.spec(
                version = "^1.0.0",
            ),
            "http_body_0_4_6": crate.spec(
                package = "http-body",
                version = "^0.4.6",
            ),
            "http-body-util": crate.spec(
                version = "^0.1.0",
            ),
            "httptest": crate.spec(
                version = "^0.15.4",
            ),
            "humantime": crate.spec(
                version = "^2.1.0",
            ),
            "hyper_0_14_27": crate.spec(
                package = "hyper",
                version = "^0.14.27",
                features = [
                    "client",
                    "full",
                    "http1",
                    "http2",
                    "server",
                    "tcp",
                ],
            ),
            "hyper": crate.spec(
                version = "^1.3.1",
                features = [
                    "full",
                ],
            ),
            "hyper-socks2": crate.spec(
                version = "^0.8.0",
                default_features = False,
                features = [
                    "rustls",
                ],
            ),
            "hyper-util": crate.spec(
                version = "^0.1.3",
                features = [
                    "full",
                ],
            ),
            "hyper-rustls": crate.spec(
                version = "^0.24.2",
                features = [
                    "http2",
                ],
            ),
            "hyper-rustls_0_27_x": crate.spec(
                default_features = False,
                package = "hyper-rustls",
                version = "^0.27.1",
                features = [
                    "http1",
                    "http2",
                    "native-tokio",
                    "ring",
                    "tls12",
                ],
            ),
            "hyperlocal-next": crate.spec(
                version = "^0.9.0",
            ),
            "ic0": crate.spec(
                version = "^0.18.11",
            ),
            "icrc1-test-env": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "icrc1-test-suite": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "ic-agent": crate.spec(
                version = "^0.35.0",
                features = [
                    "hyper",
                    "reqwest",
                    "pem",
                ],
            ),
            "ic-btc-interface": crate.spec(
                version = "^0.2.0",
            ),
            "ic-btc-validation": crate.spec(
                version = "^0.1.0",
            ),
            "ic-btc-test-utils": crate.spec(
                version = "^0.1.0",
            ),
            "ic-canister-log": crate.spec(
                version = "^0.2.0",
            ),
            "ic-cbor": crate.spec(
                version = "2.3.0",
            ),
            "ic-cdk": crate.spec(
                version = "^0.13.1",
            ),
            "ic-cdk-timers": crate.spec(
                version = "^0.7.0",
            ),
            "ic-cdk-macros": crate.spec(
                version = "^0.9.0",
            ),
            "ic-certified-map": crate.spec(
                version = "^0.3.1",
            ),
            "ic-certification": crate.spec(
                version = "2.3.0",
            ),
            "ic-http-certification": crate.spec(
                version = "2.3.0",
            ),
            "ic-metrics-encoder": crate.spec(
                version = "^1.1.1",
            ),
            "ic_principal": crate.spec(
                version = "^0.1.1",
                default_features = False,
            ),
            "ic-stable-structures": crate.spec(
                version = "^0.6.4",
            ),
            "ic-response-verification": crate.spec(
                version = "2.3.0",
            ),
            "ic-test-state-machine-client": crate.spec(
                version = "^3.0.0",
            ),
            "ic-utils": crate.spec(
                version = "^0.35.0",
                features = ["raw"],
            ),
            "ic-wasm": crate.spec(
                version = "^0.7.1",
                features = [
                    "exe",
                ],
                default_features = False,
            ),
            "ic-xrc-types": crate.spec(
                version = "^1.2.0",
            ),
            "idna": crate.spec(
                version = "^0.3.0",
            ),
            "indexmap": crate.spec(
                version = "^2.2.6",
            ),
            "indicatif": crate.spec(
                version = "^0.17.3",
            ),
            "indoc": crate.spec(
                version = "^1.0.9",
            ),
            "inferno": crate.spec(
                version = "^0.11.19",
            ),
            "insta": crate.spec(
                version = "^1.31.0",
            ),
            "instant-acme": crate.spec(
                version = "^0.3.2",
            ),
            "intmap": crate.spec(
                version = "^1.1.0",
                features = ["serde"],
            ),
            "ipnet": crate.spec(
                version = "^2.5.0",
            ),
            "isocountry": crate.spec(
                version = "^0.3.2",
            ),
            "itertools": crate.spec(
                version = "^0.12.0",
            ),
            "jemalloc-ctl": crate.spec(
                version = "^0.3.3",
            ),
            "jemallocator": crate.spec(
                version = "^0.3.2",
            ),
            "json-patch": crate.spec(
                version = "^0.2.6",
            ),
            "json5": crate.spec(
                version = "^0.4.1",
            ),
            "k256": crate.spec(
                version = "^0.13.3",
                features = [
                    "arithmetic",
                    "ecdsa",
                    "pem",
                    "pkcs8",
                    "precomputed-tables",
                    "schnorr",
                    "std",
                ],
                default_features = False,
            ),
            "k8s-openapi": crate.spec(
                version = "^0.20.0",
                features = [
                    "v1_22",
                ],
            ),
            "kube": crate.spec(
                version = "^0.87.2",
                features = [
                    "runtime",
                    "derive",
                    "ws",
                ],
            ),
            "lazy_static": crate.spec(
                version = "^1.4.0",
            ),
            "leb128": crate.spec(
                version = "^0.2.5",
            ),
            "libc": crate.spec(
                version = "^0.2.155",
            ),
            "libflate": crate.spec(
                version = "^1.1.2",
            ),
            "libfuzzer-sys": crate.spec(
                version = "^0.4.7",
                default_features = False,
            ),
            "libsecp256k1": crate.spec(
                version = "^0.7.0",
            ),
            "libnss": crate.spec(
                version = "^0.5.0",
            ),
            "little-loadshedder": crate.spec(
                version = "^0.1.0",
            ),
            "local-ip-address": crate.spec(
                version = "^0.5.6",
            ),
            "log": crate.spec(
                version = "^0.4.14",
            ),
            "lru": crate.spec(
                version = "^0.7.8",
                default_features = False,
            ),
            "mach2": crate.spec(
                # Wasmtime depends on 0.4.2 but specifies 0.4.1.
                # Enforce 0.4.2 using a dummy dependency until
                # the upstream issue is fixed.
                version = "^0.4.2",
            ),
            "maplit": crate.spec(
                version = "^1.0.2",
            ),
            "maxminddb": crate.spec(
                version = "^0.24",
            ),
            "metrics-proxy": crate.spec(
                git = "https://github.com/dfinity/metrics-proxy.git",
                rev = "b6933ed79ac07baee7f3fbc0793bed95e614d27c",
                # When updating this, please make sure that the built
                # binary exports metrics http_cache_* after one
                # successful request to the proxy.  The OpenTelemetry
                # package version pinned by this software must equal
                # the OpenTelemetry version pinned by the
                # axum-otel-metrics version pinned by this software,
                # due to technical idiosyncrasies of the OpenTelemetry
                # crate.  When these do not match, custom metrics are
                # not exported.
                default_features = False,
                features = [
                    "rustls-tls-webpki-roots",
                ],
            ),
            "minicbor": crate.spec(
                version = "^0.19.1",
                features = ["alloc", "derive"],
            ),
            "minicbor-derive": crate.spec(
                version = "^0.13.0",
            ),
            "mockall": crate.spec(
                version = "^0.12.1",
            ),
            "mockito": crate.spec(
                version = "^1.2.0",
            ),
            "moka": crate.spec(
                version = "^0.12",
                features = [
                    "future",
                    "sync",
                ],
            ),
            "more-asserts": crate.spec(
                version = "^0.3.1",
            ),
            "nftables": crate.spec(
                version = "^0.4",
            ),
            "nix": crate.spec(
                version = "^0.24.3",
            ),
            "num": crate.spec(
                version = "^0.4.0",
            ),
            "num-bigint": crate.spec(
                version = "^0.4.0",
            ),
            "num-bigint-dig": crate.spec(
                version = "^0.8",
                features = ["prime"],
            ),
            "num-rational": crate.spec(
                version = "^0.2.2",
            ),
            "num-traits": crate.spec(
                version = "^0.2.12",
                features = [
                    "libm",
                ],
                default_features = False,
            ),
            "num_cpus": crate.spec(
                version = "^1.13.1",
            ),
            "once_cell": crate.spec(
                version = "^1.8",
            ),
            "openssh-keys": crate.spec(
                version = "^0.5.0",
            ),
            "opentelemetry": crate.spec(
                version = "^0.23.0",
                features = [
                    "metrics",
                    "trace",
                ],
            ),
            "opentelemetry_0_20_0": crate.spec(
                package = "opentelemetry",
                version = "^0.20.0",
                features = [
                    "metrics",
                    "trace",
                ],
            ),
            "opentelemetry-otlp": crate.spec(
                version = "^0.16.0",
                features = [
                    "grpc-tonic",
                ],
            ),
            "opentelemetry_sdk": crate.spec(
                version = "^0.23.0",
                features = [
                    "trace",
                    "rt-tokio",
                ],
            ),
            "opentelemetry-prometheus": crate.spec(
                version = "^0.16.0",
            ),
            "opentelemetry-prometheus_0_13_0": crate.spec(
                package = "opentelemetry-prometheus",
                version = "^0.13.0",
            ),
            "p256": crate.spec(
                version = "^0.13.2",
                features = [
                    "arithmetic",
                    "ecdsa",
                    "pem",
                    "pkcs8",
                ],
                default_features = False,
            ),
            "pairing": crate.spec(
                version = "^0.22",
            ),
            "parking_lot": crate.spec(
                version = "^0.12.1",
            ),
            "paste": crate.spec(
                version = "^1.0.0",
            ),
            "pathdiff": crate.spec(
                version = "^0.2.1",
            ),
            "pcre2": crate.spec(
                version = "^0.2.6",
            ),
            "pem": crate.spec(
                version = "^1.0.1",
            ),
            "pin-project-lite": crate.spec(
                version = "^0.2",
            ),
            "ping": crate.spec(
                version = "^0.5.0",
            ),
            "pkcs8": crate.spec(
                version = "^0.10.2",
            ),
            "pkg-config": crate.spec(
                version = "^0.3",
            ),
            "pprof": crate.spec(
                version = "^0.13.0",
                features = [
                    "flamegraph",
                    "prost-codec",
                ],
                default_features = False,
            ),
            "predicates": crate.spec(
                version = "^3.0.4",
            ),
            "pretty-bytes": crate.spec(
                version = "^0.2.2",
            ),
            "pretty_assertions": crate.spec(
                version = "^1.4.0",
            ),
            "priority-queue": crate.spec(
                version = "^1.3.1",
                features = [
                    "serde",
                ],
            ),
            "proc-macro2": crate.spec(
                version = "^1.0",
            ),
            "procfs": crate.spec(
                version = "^0.9",
                default_features = False,
            ),
            "prometheus": crate.spec(
                version = "^0.13.4",
                features = [
                    "process",
                ],
            ),
            "proptest": crate.spec(
                version = "^1.0.0",
            ),
            "prometheus-parse": crate.spec(
                version = "^0.2.4",
            ),
            "proptest-derive": crate.spec(
                version = "^0.3.0",
            ),
            "prost": crate.spec(
                version = "^0.12",
            ),
            "prost-build": crate.spec(
                version = "^0.12",
            ),
            "prost-derive": crate.spec(
                version = "^0.12",
            ),
            "protobuf": crate.spec(
                version = "^2.28.0",
            ),
            "publicsuffix": crate.spec(
                version = "^2.2.3",
            ),
            "quickcheck": crate.spec(
                version = "^1.0.3",
            ),
            "quinn": crate.spec(
                version = "^0.10.2",
                features = [
                    "ring",
                ],
            ),
            "quinn-udp": crate.spec(
                version = "^0.5.1",
            ),
            "quote": crate.spec(
                version = "^1.0",
            ),
            "rand": crate.spec(
                version = "^0.8.5",
                features = [
                    "small_rng",
                ],
            ),
            "rand_chacha": crate.spec(
                version = "^0.3.1",
            ),
            "rand_distr": crate.spec(
                version = "^0.4",
            ),
            "rand_pcg": crate.spec(
                version = "^0.3.1",
            ),
            "randomkit": crate.spec(
                version = "^0.1.1",
            ),
            "ratelimit": crate.spec(
                version = "^0.9.1",
            ),
            "rayon": crate.spec(
                version = "^1.10.0",
            ),
            "rcgen": crate.spec(
                version = "^0.13.1",
                features = [
                    "zeroize",
                ],
            ),
            "rgb": crate.spec(
                version = "^0.8.37",
            ),
            "regex": crate.spec(
                version = "^1.10.4",
            ),
            "reqwest_0_11_27": crate.spec(
                package = "reqwest",
                version = "^0.11.27",
                default_features = False,
                features = [
                    "blocking",
                    "json",
                    "multipart",
                    "rustls-tls-webpki-roots",
                    "socks",
                    "stream",
                ],
            ),
            "reqwest": crate.spec(
                package = "reqwest",
                version = "^0.12.3",
                default_features = False,
                features = [
                    "blocking",
                    "http2",
                    "json",
                    "multipart",
                    "rustls-tls",
                    "rustls-tls-native-roots",
                    "stream",
                ],
            ),
            "ring": crate.spec(
                version = "^0.17.7",
                features = [
                    "std",
                ],
            ),
            "ripemd": crate.spec(
                version = "^0.1.1",
            ),
            "rlp": crate.spec(
                version = "^0.5.2",
            ),
            "rocksdb": crate.spec(
                version = "^0.22.0",
                default_features = False,
            ),
            "rolling-file": crate.spec(
                version = "^0.2.0",
            ),
            "rsa": crate.spec(
                version = "^0.9.2",
                features = ["sha2"],
            ),
            "rstack-self": crate.spec(
                version = "^0.3",
            ),
            "rstest": crate.spec(
                version = "^0.19",
            ),
            "rusb": crate.spec(
                version = "0.9",
            ),
            "rusqlite": crate.spec(
                version = "^0.28.0",
                features = ["bundled"],
            ),
            "rust_decimal": crate.spec(
                version = "^1.25.0",
            ),
            "rust_decimal_macros": crate.spec(
                version = "^1.25.0",
            ),
            "rustc-hash": crate.spec(
                version = "^1.1.0",
            ),
            "rustls_0_21_12": crate.spec(
                package = "rustls",
                version = "^0.21.12",
                features = [
                    "dangerous_configuration",
                ],
            ),
            "rustls": crate.spec(
                package = "rustls",
                default_features = False,
                version = "^0.23.8",
                features = [
                    "ring",
                ],
            ),
            "rustls-native-certs": crate.spec(
                version = "^0.7.0",
            ),
            "rustls-pemfile": crate.spec(
                version = "^2.1.2",
            ),
            "rustls-pki-types": crate.spec(
                version = "^1.7.0",
                features = [
                    "alloc",
                ],
            ),
            "rustversion": crate.spec(
                version = "^1.0",
            ),
            "rusty-fork": crate.spec(
                version = "^0.3.0",
            ),
            "schemars": crate.spec(
                version = "^0.8.16",
            ),
            "schnorr_fun": crate.spec(
                version = "^0.10",
            ),
            "scoped_threadpool": crate.spec(
                version = "^0.1.9",
            ),
            "scopeguard": crate.spec(
                version = "^1.1.0",
            ),
            "scraper": crate.spec(
                version = "^0.17.1",
            ),
            "semver": crate.spec(
                version = "^1.0.9",
                features = [
                    "serde",
                ],
            ),
            "serde": crate.spec(
                version = "^1.0.203",
                features = [
                    "derive",
                ],
                default_features = False,
            ),
            "serde-bytes-repr": crate.spec(
                version = "^0.1.5",
            ),
            "serde_bytes": crate.spec(
                version = "^0.11.14",
            ),
            "serde_cbor": crate.spec(
                version = "^0.11.2",
            ),
            "serde_json": crate.spec(
                version = "^1.0.107",
            ),
            "serde_regex": crate.spec(
                version = "^1.1.0",
            ),
            "serde_with": crate.spec(
                version = "^1.14.0",
            ),
            "serde_yaml": crate.spec(
                version = "^0.9.33",
            ),
            "sha2-0_9_1": crate.spec(
                package = "sha2",
                version = "^0.9.1",
            ),
            "sha3": crate.spec(
                version = "^0.9.1",
            ),
            "signal-hook": crate.spec(
                version = "^0.3.6",
                features = [
                    "iterator",
                ],
            ),
            "signature": crate.spec(
                version = "^2.2.0",
            ),
            "simple_asn1": crate.spec(
                version = "^0.6.2",
            ),
            "simple_moving_average": crate.spec(
                version = "^1.0.2",
            ),
            "slog": crate.spec(
                version = "^2.7.0",
                features = [
                    "max_level_trace",
                    "nested-values",
                    "release_max_level_debug",
                    "release_max_level_trace",
                ],
            ),
            "slog-async": crate.spec(
                version = "^2.8.0",
                features = [
                    "nested-values",
                ],
            ),
            "slog-envlogger": crate.spec(
                version = "^2.2.0",
            ),
            "slog-json": crate.spec(
                version = "^2.6.1",
                features = [
                    "nested-values",
                ],
            ),
            "slog-scope": crate.spec(
                version = "^4.4.0",
            ),
            "slog-term": crate.spec(
                version = "^2.9.1",
            ),
            "socket2": crate.spec(
                version = "^0.5.7",
                features = [
                    "all",
                ],
            ),
            "ssh2": crate.spec(
                version = "0.9.4",
            ),
            "strum": crate.spec(
                version = "^0.26.2",
                features = [
                    "derive",
                ],
            ),
            "strum_macros": crate.spec(
                version = "^0.26.2",
            ),
            "stubborn-io": crate.spec(
                version = "^0.3.2",
            ),
            "substring": crate.spec(
                version = "^1.4.5",
            ),
            "subtle": crate.spec(
                version = "^2.4",
            ),
            "syn": crate.spec(
                version = "^1.0.109",
                features = [
                    "fold",
                    "full",
                ],
            ),
            "sync_wrapper": crate.spec(
                version = "^1.0.1",
            ),
            "tar": crate.spec(
                version = "^0.4.38",
            ),
            "tarpc": crate.spec(
                version = "^0.34",
                features = [
                    "full",
                ],
            ),
            "tempfile": crate.spec(
                version = "^3.10.1",
            ),
            "tester": crate.spec(
                version = "^0.7.0",
            ),
            "test-strategy": crate.spec(
                version = "^0.3.1",
            ),
            "textplots": crate.spec(
                version = "^0.8",
            ),
            "thiserror": crate.spec(
                version = "^1.0.57",
            ),
            "thousands": crate.spec(
                version = "^0.2.0",
            ),
            "threadpool": crate.spec(
                version = "^1.8.1",
            ),
            "time": crate.spec(
                version = "^0.3.36",
            ),
            "tokio": crate.spec(
                version = "^1.38.0",
                features = [
                    "full",
                ],
            ),
            "tokio-io-timeout": crate.spec(
                version = "^1.2.0",
            ),
            "tokio-metrics": crate.spec(
                version = "^0.3.1",
            ),
            "tokio_rustls_0_24_1": crate.spec(
                package = "tokio-rustls",
                version = "^0.24.1",
                features = [
                    "dangerous_configuration",
                ],
            ),
            "tokio-rustls": crate.spec(
                version = "^0.26.0",
                default_features = False,
                features = [
                    "logging",
                    "tls12",
                    "ring",
                ],
            ),
            "tokio-serde": crate.spec(
                version = "^0.8",
                features = [
                    "bincode",
                    "json",
                ],
            ),
            "tokio-socks": crate.spec(
                version = "^0.5.1",
            ),
            "tokio-test": crate.spec(
                version = "^0.4.2",
            ),
            "tokio-util": crate.spec(
                version = "^0.7.11",
                features = [
                    "codec",
                    "time",
                    "rt",
                ],
            ),
            "toml": crate.spec(
                version = "^0.5.9",
            ),
            "tonic": crate.spec(
                version = "^0.11.0",
            ),
            "tonic-build": crate.spec(
                version = "^0.11.0",
            ),
            "tower": crate.spec(
                version = "^0.4.13",
                features = ["full"],
            ),
            "tower_http_0_4_4": crate.spec(
                version = "^0.4.4",
                package = "tower-http",
                features = [
                    "trace",
                    "request-id",
                    "util",
                    "compression-full",
                ],
            ),
            "tower-http": crate.spec(
                version = "^0.5.2",
                features = [
                    "cors",
                    "limit",
                    "trace",
                    "request-id",
                    "util",
                    "compression-full",
                    "tracing",
                ],
            ),
            "tower_governor": crate.spec(
                version = "^0.1",
            ),
            "tower-request-id": crate.spec(
                version = "^0.3.0",
            ),
            "tower-test": crate.spec(
                version = "^0.4.0",
            ),
            "tracing": crate.spec(
                version = "^0.1.40",
            ),
            "tracing-appender": crate.spec(
                version = "^0.2.3",
            ),
            "tracing-flame": crate.spec(
                version = "^0.2.0",
            ),
            "tracing-core": crate.spec(
                version = "^0.1.32",
            ),
            "tracing-opentelemetry": crate.spec(
                version = "^0.24.0",
            ),
            "tracing-serde": crate.spec(
                version = "^0.1.3",
            ),
            "tracing-slog": crate.spec(
                version = "^0.2",
            ),
            "tracing-subscriber": crate.spec(
                version = "^0.3.18",
                features = [
                    "env-filter",
                    "fmt",
                    "json",
                ],
            ),
            "trust-dns-resolver": crate.spec(
                version = "^0.22.0",
            ),
            "turmoil": crate.spec(
                version = "^0.6.2",
            ),
            "url": crate.spec(
                version = "^2.4.1",
                features = [
                    "serde",
                ],
            ),
            "uuid": crate.spec(
                version = "^1.3.0",
                features = [
                    "v4",
                    "serde",
                ],
            ),
            "vsock": crate.spec(
                version = "^0.4",
            ),
            "walrus": crate.spec(
                version = "^0.19.0",
            ),
            "walkdir": crate.spec(
                version = "^2.3.1",
            ),
            "warp": crate.spec(
                version = "^0.3.6",
                features = [
                    "tls",
                ],
            ),
            "wasm-bindgen": crate.spec(
                version = "^0.2",
            ),
            "wasm-encoder": crate.spec(
                version = "^0.201.0",
                features = [
                    "wasmparser",
                ],
            ),
            "wasm-smith": crate.spec(
                version = "^0.201.0",
                default_features = False,
                features = [
                    "wasmparser",
                ],
            ),
            "wasmparser": crate.spec(
                version = "^0.201.0",
            ),
            "wasmprinter": crate.spec(
                version = "^0.2.50",
            ),
            "wasmtime": crate.spec(
                version = "^21.0.1",
                default_features = False,
                features = [
                    "cranelift",
                    "gc",
                    "parallel-compilation",
                    "runtime",
                ],
            ),
            "wasmtime-environ": crate.spec(
                version = "^21.0.1",
            ),
            "wast": crate.spec(
                version = "^53.0.0",
            ),
            "wat": crate.spec(
                version = "^1.0.57",
            ),
            "wee_alloc": crate.spec(
                version = "^0.4.3",
            ),
            "which": crate.spec(
                version = "^4.2.2",
            ),
            "wsl": crate.spec(
                version = "^0.1.0",
            ),
            "wycheproof": crate.spec(
                version = "^0.5",
            ),
            "wiremock": crate.spec(
                version = "^0.5.19",
            ),
            "x509-cert": crate.spec(
                version = "^0.2.5",
                features = [
                    "builder",
                    "hazmat",
                ],
            ),
            "x509-parser": crate.spec(
                version = "^0.16.0",
            ),
            "yansi": crate.spec(
                version = "^0.5.0",
            ),
            "zeroize": crate.spec(
                version = "^1.8.1",
                features = [
                    "zeroize_derive",
                ],
            ),
            "zstd": crate.spec(
                version = "^0.13.1",
            ),
        },
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
    )
