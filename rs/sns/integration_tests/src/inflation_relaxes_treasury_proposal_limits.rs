use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::E8;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_nns_test_utils::state_test_helpers::sns_make_proposal;
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic;
use ic_sns_governance::pb::v1::{Proposal, proposal::Action, TransferSnsTreasuryFunds, NeuronId, transfer_sns_treasury_funds::TransferFrom};
use ic_types::Cycles;
use lazy_static::lazy_static;
use std::str::FromStr;

lazy_static! {
    // Callee.
    static ref SNS_GOVERNANCE_CANISTER_ID: CanisterId =
        CanisterId::try_from_principal_id(PrincipalId::from_str("zqfso-syaaa-aaaaq-aaafq-cai").unwrap()).unwrap();

    // Caller.
    static ref PROPOSER_PRINCIPAL_ID: PrincipalId =
        PrincipalId::from_str("gmk4q-vviqd-2vtq3-qmkcv-lbji5-pg2ca-g4rnn-r5cid-7rvm6-yxurj-pqe")
        .unwrap();
    static ref PROPOSER_NEURON_ID: NeuronId = NeuronId {
        id: vec![
            0x00, 0x0c, 0x03, 0x4e, 0x22, 0x99, 0x6c, 0xe0, 0xdd, 0x9c, 0x14, 0x77,
            0x18, 0x20, 0x56, 0xc7, 0xa5, 0x6e, 0x00, 0xe0, 0x31, 0x8e, 0x32, 0xe4,
            0x83, 0xa1, 0x63, 0xa6, 0x0d, 0x57, 0xb9, 0xc7,
        ],
    };
}

#[test]
fn test_inflation_relaxes_treasury_proposal_limits() {
    // Step 1: Prepare the world.

    // This is very heavy, but we do it for realistic data. Most of the data
    // loaded here is not used.
    let state_machine = new_state_machine_with_golden_sns_state_or_panic();

    eprintln!();
    eprintln!("Creating stub cycles minting canister...");
    // Create stub cycles minting canister.
    //
    // This is needed to get the price of ICP. It is probably surprising that
    // such data is fetched from CMC instead of the exchange rate canister, but
    // this is nevertheless whence SNS governance canisters source such data.
    state_machine.create_canister_with_cycles(
        Some(PrincipalId::from(CYCLES_MINTING_CANISTER_ID)),
        Cycles::from(u64::MAX), // We do not care about this.
        None, // settings
    );
    state_machine.install_existing_canister(
        CYCLES_MINTING_CANISTER_ID,
        Project::cargo_bin_maybe_from_env("stub-cycles-minting", /* features = */ &[]).bytes(),
        vec![], // init args
    )
        .unwrap();
    eprintln!("DONE creating stub cycles minting canister.");
    eprintln!();

    // Install the latest and greatest SNS Governance code (takes inflation into account).
    eprintln!();
    eprintln!("Upgrading SNS governance canister...");
    state_machine.upgrade_canister(
        *SNS_GOVERNANCE_CANISTER_ID,
        Project::cargo_bin_maybe_from_env("sns-governance-canister", /* features = */ &[]).bytes(),
        vec![], // upgrade args
    )
    .unwrap();
    eprintln!("DONE upgrading SNS governance canister.");
    eprintln!();

    // Step 2: Call the code under test. Specifically, propose to take some SNS
    // tokens from an SNS treasury. When inflation is not considered, the
    // proposal is blocked due to the treasury being (greatly) over-valued. But
    // with inflation, the proposal amount limit is relaxed, and thus the
    // proposal is allowed.

    let result = sns_make_proposal(
        &state_machine,
        *SNS_GOVERNANCE_CANISTER_ID,
        *PROPOSER_PRINCIPAL_ID, // caller
        PROPOSER_NEURON_ID.clone(),
        Proposal {
            title: "Making it Rain".to_string(),
            summary: "Send a heap of SNS tokens to some lucky guy.".to_string(),
            url: "https://forum.dfinity.org/make-it-rain".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury as i32,
                amount_e8s: 1_000_000 * E8, // Currently, this is worth about 3_300 USD.
                to_principal: Some(PrincipalId::new_user_test_id(42)),
                to_subaccount: None,
                memo: None,
            })),
        }
    );

    // Step 3: Inspect results.

    // Without taking inflation into account, this panics.
    result.unwrap();
}
