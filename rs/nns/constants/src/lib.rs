use ic_base_types::CanisterId;
use maplit::btreemap;

// WARNING: The NNS canisters MUST be installed in the NNS subnet,
// in the following order, otherwise they won't be able to find
// each other.
//
// These constants are used to write a file with the PB below in
// nns/common/build.rs.
//
// NOTES (IMPORTANT!)
// ~~~~~~~~~~~~~~~~~~
// - This is dependent on the implementation of function
//   `CanisterManager::generate_new_canister_id`.
// - Unless you only add at the end, be sure to double check with
//   `rs/nns/canister_ids.json`. TODO: Write a test that enforces
//   that this file matches the .json file
pub const REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 0;
pub const GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 1;
pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
pub const ROOT_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 3;
pub const CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 4;
pub const LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 5;
pub const GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 6;
pub const IDENTITY_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 7;
pub const NNS_UI_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 8;
pub const ICP_LEDGER_ARCHIVE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 9;
pub const SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 10;
pub const LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 11;
pub const ICP_LEDGER_ARCHIVE_1_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 12;
pub const SUBNET_RENTAL_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 13;
pub const ICP_LEDGER_ARCHIVE_2_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 14;
// Exchange Rate, Cycles Ledger (Index) Canisters are deployed to the II subnet.
pub const EXCHANGE_RATE_CANISTER_INDEX: u64 = 0x2100001;
pub const CYCLES_LEDGER_CANISTER_INDEX: u64 = 0x2100002;
pub const CYCLES_LEDGER_INDEX_CANISTER_INDEX: u64 = 0x2100003;
// Bitcoin canisters are deployed to the `w4rem` subnet
pub const BITCOIN_TESTNET_CANISTER_INDEX: u64 = 0x1a00001;
pub const BITCOIN_MAINNET_CANISTER_INDEX: u64 = 0x1a00004;
// SNS Aggregator canister is deployed to the `x33ed` (SNS) subnet.
pub const SNS_AGGREGATOR_CANISTER_INDEX: u64 = 0x2000010;

/// WARNING: This list is incomplete. In particular, this does NOT include
/// ledger archive, nor ledger index.
///
/// The names of all expected .wasm files to set up the NNS.
///
/// As of May, 2024, this is only used by nns/init/src/main.rs, which is only
/// run when creating a new net (e.g. mainnet, or testnet). For whatever reason,
/// that doesn't need ledger archive, nor ledger index. (I guess because those
/// are spawned by ledger.) Thus, they are not included.
pub const NNS_CANISTER_WASMS: [&str; 13] = [
    "registry-canister",
    "governance-canister",
    "governance-canister_test",
    "ledger-canister_notify-method",
    "root-canister",
    "cycles-minting-canister",
    // The lifeline is built differently, which explains why its wasm has a different name pattern.
    "lifeline_canister",
    "genesis-token-canister",
    "identity-canister",
    "nns-ui-canister",
    "sns-wasm-canister",
    "ic-icrc1-ledger",
    "ic-ckbtc-minter",
];

/// WARNING: This count is incomplete. See comments on NNS_CANISTER_WASMS.
///
/// As of May 2024, this is only used by nns itest_helpers.
pub const NUM_NNS_CANISTERS: usize = ALL_NNS_CANISTER_IDS.len();

/// 0: rwlgt-iiaaa-aaaaa-aaaaa-cai
pub const REGISTRY_CANISTER_ID: CanisterId =
    CanisterId::from_u64(REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET);
/// 1: rrkah-fqaaa-aaaaa-aaaaq-cai
pub const GOVERNANCE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET);
/// 2: ryjl3-tyaaa-aaaaa-aaaba-cai
pub const LEDGER_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
/// 3: r7inp-6aaaa-aaaaa-aaabq-cai
pub const ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(ROOT_CANISTER_INDEX_IN_NNS_SUBNET);
/// 4: rkp4c-7iaaa-aaaaa-aaaca-cai
pub const CYCLES_MINTING_CANISTER_ID: CanisterId =
    CanisterId::from_u64(CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET);
/// 5: rno2w-sqaaa-aaaaa-aaacq-cai
pub const LIFELINE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET);
/// 6: renrk-eyaaa-aaaaa-aaada-cai
pub const GENESIS_TOKEN_CANISTER_ID: CanisterId =
    CanisterId::from_u64(GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET);
/// 7: rdmx6-jaaaa-aaaaa-aaadq-cai
pub const IDENTITY_CANISTER_ID: CanisterId =
    CanisterId::from_u64(IDENTITY_CANISTER_INDEX_IN_NNS_SUBNET);
/// 8: qoctq-giaaa-aaaaa-aaaea-cai
pub const NNS_UI_CANISTER_ID: CanisterId =
    CanisterId::from_u64(NNS_UI_CANISTER_INDEX_IN_NNS_SUBNET);
/// 9: qjdve-lqaaa-aaaaa-aaaeq-cai
pub const ICP_LEDGER_ARCHIVE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(ICP_LEDGER_ARCHIVE_CANISTER_INDEX_IN_NNS_SUBNET);
/// 10: qaa6y-5yaaa-aaaaa-aaafa-cai
pub const SNS_WASM_CANISTER_ID: CanisterId =
    CanisterId::from_u64(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET);
/// 11: qhbym-qaaaa-aaaaa-aaafq-cai
pub const LEDGER_INDEX_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET);
/// 12: qsgjb-riaaa-aaaaa-aaaga-cai
pub const ICP_LEDGER_ARCHIVE_1_CANISTER_ID: CanisterId =
    CanisterId::from_u64(ICP_LEDGER_ARCHIVE_1_CANISTER_INDEX_IN_NNS_SUBNET);
/// 13: qvhpv-4qaaa-aaaaa-aaagq-cai
pub const SUBNET_RENTAL_CANISTER_ID: CanisterId =
    CanisterId::from_u64(SUBNET_RENTAL_CANISTER_INDEX_IN_NNS_SUBNET);
/// 14: q4eej-kyaaa-aaaaa-aaaha-cai
pub const ICP_LEDGER_ARCHIVE_2_CANISTER_ID: CanisterId =
    CanisterId::from_u64(ICP_LEDGER_ARCHIVE_2_CANISTER_INDEX_IN_NNS_SUBNET);
/// 0x2_100_001 (34_603_009): uf6dk-hyaaa-aaaaq-qaaaq-cai
pub const EXCHANGE_RATE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(EXCHANGE_RATE_CANISTER_INDEX);
/// 0x2_100_002 (34_603_010): um5iw-rqaaa-aaaaq-qaaba-cai
pub const CYCLES_LEDGER_CANISTER_ID: CanisterId =
    CanisterId::from_u64(CYCLES_LEDGER_CANISTER_INDEX);
/// 0x2_100_003 (34_603_011): ul4oc-4iaaa-aaaaq-qaabq-cai
pub const CYCLES_LEDGER_INDEX_CANISTER_ID: CanisterId =
    CanisterId::from_u64(CYCLES_LEDGER_INDEX_CANISTER_INDEX);
/// 0x1_a00_001 (27_262_977): g4xu7-jiaaa-aaaan-aaaaq-cai
pub const BITCOIN_TESTNET_CANISTER_ID: CanisterId =
    CanisterId::from_u64(BITCOIN_TESTNET_CANISTER_INDEX);
/// 0x1_a00_004 (27_262_980): ghsi2-tqaaa-aaaan-aaaca-cai
pub const BITCOIN_MAINNET_CANISTER_ID: CanisterId =
    CanisterId::from_u64(BITCOIN_MAINNET_CANISTER_INDEX);
/// 0x2_000_010 (33_554_448): 3r4gx-wqaaa-aaaaq-aaaia-cai
pub const SNS_AGGREGATOR_CANISTER_ID: CanisterId =
    CanisterId::from_u64(SNS_AGGREGATOR_CANISTER_INDEX);

/// WARNING: This list is incomplete. In particular, this does NOT include
/// ledger archive, nor ledger index.
///
/// As of May 2024, it looks like this is only used by (a whole bunch of) tests, mostly as the
/// argument to send_whitelist.
pub const ALL_NNS_CANISTER_IDS: [&CanisterId; 10] = [
    &REGISTRY_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &CYCLES_MINTING_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
    &GENESIS_TOKEN_CANISTER_ID,
    &IDENTITY_CANISTER_ID,
    &NNS_UI_CANISTER_ID,
    &SNS_WASM_CANISTER_ID,
];

// The memory allocation for the ledger, governance and registry canisters
// (4GiB)
const NNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

// We preallocate 10GB stable memory for NNS governance so that pre_upgrade never fails trying to
// grow stable memory, and we might also have some other data occupying stable memory.
const NNS_GOVERNANCE_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 10 * 1024 * 1024 * 1024;

// The default memory allocation to set for the remaining NNS canister (1GiB)
const NNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 1024 * 1024 * 1024;

/// The current value is 4 GiB, s.t. the SNS governance canister never hits the soft memory limit.
/// This mitigates the risk that an SNS Governance canister runs out of memory and proposals cannot
/// be passed anymore.
pub const DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT: u64 = 1 << 32;

/// Returns the memory allocation of the given nns canister.
pub fn memory_allocation_of(canister_id: CanisterId) -> u64 {
    if canister_id == GOVERNANCE_CANISTER_ID {
        NNS_GOVERNANCE_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    } else if [LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID].contains(&canister_id) {
        NNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    } else {
        NNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    }
}

pub fn canister_id_to_nns_canister_name(canister_id: CanisterId) -> String {
    let id_to_name = btreemap! { // TODO: Make this const. btreemap does not support this.
        CYCLES_MINTING_CANISTER_ID       => "cycles-minting",
        EXCHANGE_RATE_CANISTER_ID        => "exchange-rate",
        GENESIS_TOKEN_CANISTER_ID        => "genesis-token",
        GOVERNANCE_CANISTER_ID           => "governance",
        ICP_LEDGER_ARCHIVE_1_CANISTER_ID => "icp-ledger-archive-1",
        ICP_LEDGER_ARCHIVE_2_CANISTER_ID => "icp-ledger-archive-2",
        ICP_LEDGER_ARCHIVE_CANISTER_ID   => "icp-ledger-archive",
        IDENTITY_CANISTER_ID             => "identity",
        LEDGER_CANISTER_ID               => "ledger",
        LEDGER_INDEX_CANISTER_ID         => "ledger-index",
        LIFELINE_CANISTER_ID             => "lifeline",
        NNS_UI_CANISTER_ID               => "nns-ui",
        REGISTRY_CANISTER_ID             => "registry",
        ROOT_CANISTER_ID                 => "root",
        SNS_WASM_CANISTER_ID             => "sns-wasm",
        SUBNET_RENTAL_CANISTER_ID        => "subnet-rental",
    };
    debug_assert_eq!(
        id_to_name.len(),
        // Because 0 through 14 accounts for the first 15 canister +
        // 1 for exchange rate canister.
        16,
        "{:#?}",
        id_to_name
    );

    id_to_name
        .get(&canister_id)
        .map(|name| name.to_string())
        .unwrap_or_else(|| format!("{}", canister_id))
}
