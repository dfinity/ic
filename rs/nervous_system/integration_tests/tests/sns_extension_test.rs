use candid::{Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nervous_system_agent::{
    CallCanisters,
    pocketic_impl::PocketIcAgent,
    sns::{
        Sns,
        governance::{ProposalSubmissionError, SubmittedProposal},
    },
};
use ic_nervous_system_common::{
    E8, ONE_MONTH_SECONDS, ledger::compute_distribution_subaccount_bytes,
};
use ic_nervous_system_common_test_utils::wasm_helpers::SMALLEST_VALID_WASM_BYTES;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        NnsInstaller, add_wasms_to_sns_wasm, cycles_ledger, install_canister_with_controllers,
        load_registry_mutations, nns, sns, sns::governance::propose_and_wait,
    },
};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_sns_cli::{
    neuron_id_to_candid_subaccount::ParsedSnsNeuron,
    register_extension,
    register_extension::{RegisterExtensionArgs, RegisterExtensionInfo},
};
use ic_sns_governance::{
    governance::TREASURY_SUBACCOUNT_NONCE,
    pb::v1::{AddAllowedExtensionRequest, ExtensionSpec},
};
use ic_sns_governance_api::pb::v1::{
    ChunkedCanisterWasm, ExecuteExtensionOperation, ExtensionInit, ExtensionOperationArg,
    ExtensionUpgradeArg, GovernanceError, NeuronId, PreciseValue, Proposal, RegisterExtension,
    UpgradeExtension, Wasm as ApiWasm, governance_error, proposal::Action,
};
use ic_sns_root::pb::v1::ListSnsCanistersRequest;
use ic_sns_swap::pb::v1::Lifecycle;
use ic_test_utilities::universal_canister::{
    get_universal_canister_wasm, get_universal_canister_wasm_sha256,
};
use icp_ledger::{DEFAULT_TRANSFER_FEE, Tokens};
use icrc_ledger_types::{icrc::generic_value::Value, icrc1::account::Account};
use maplit::btreemap;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use pretty_assertions::assert_eq;
use sns_treasury_manager::{Asset, AuditTrailRequest, BalanceBook, BalancesRequest};
use std::{io::Write, path::PathBuf, str::FromStr, time::Duration};
use tempfile::{NamedTempFile, TempDir};
use url::Url;

mod src {
    pub use ic_nns_governance_api::create_service_nervous_system::{
        InitialTokenDistribution,
        initial_token_distribution::{
            DeveloperDistribution, SwapDistribution, TreasuryDistribution,
            developer_distribution::NeuronDistribution,
        },
    };
} // end mod src

const ICP_FEE: u64 = DEFAULT_TRANSFER_FEE.get_e8s();
const SNS_FEE: u64 = 11143;

#[tokio::test]
async fn test_treasury_manager() {
    do_test_treasury_manager().await
}

#[tokio::test]
async fn test_existing_extension_wasm_rejected() {
    run_existing_extension_wasm_rejected_test().await
}

#[tokio::test]
async fn test_clean_up_failed_register_extension() {
    // Step 1: Prepare the world. This mainly consists of creating NNS canister,
    // and creating an SNS.

    let state_dir = TempDir::new().unwrap().path().to_path_buf();

    let World {
        pocket_ic,
        fiduciary_subnet_id,
        sns,
        sns_root_canister_id,
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
        neuron_id,
        sender,

        sns_ledger_canister_id: _,
        initial_icp_balance_e8s: _,
        initial_sns_balance_e8s: _,
    } = prepare_the_world(state_dir).await;

    let agent = PocketIcAgent::new(&pocket_ic, sender);

    // Step 2: Run the code under test, i.e. clean_up_failed_register_extension.

    // This triggers an injected fault during execution of the RegisterExtension
    // proposal. That way, we can trigger clean_up_failed_register_extension,
    // the code under test.
    let mut smallest_wasm_file = NamedTempFile::new().unwrap();
    smallest_wasm_file
        .write_all(SMALLEST_VALID_WASM_BYTES)
        .unwrap();

    let icp = Tokens::from_tokens(10).unwrap();
    cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

    let RegisterExtensionInfo {
        proposal_id,
        extension_canister_id,
        wasm_module_hash: _,
    } = register_extension::exec(
        RegisterExtensionArgs {
            sns_neuron_id: Some(ParsedSnsNeuron(neuron_id.clone())),
            sns_root_canister_id,
            subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
            wasm_path: smallest_wasm_file.path().to_path_buf(),
            proposal_url: Url::try_from("https://example.com").unwrap(),
            summary: "Register KongSwap Adaptor".to_string(),
            extension_init: make_deposit_allowances(
                initial_treasury_allocation_icp_e8s,
                initial_treasury_allocation_sns_e8s,
            ),
            network: None,
        },
        &agent,
    )
    .await
    .unwrap();

    let proposal_id = proposal_id.unwrap();

    for _ in 0..100 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(1)).await;
    }

    // Step 3: Verify results.

    // Step 3.1: First of all, the code under test is only triggered when there
    // is a problem with RegisterExtension proposal execution, so before we even
    // attempt to verify that clean_up_failed_register_extension did what it is
    // supposed to, let's look at whether it would have even been triggered at
    // all.
    let _err = sns::governance::wait_for_proposal_execution(
        &pocket_ic,
        sns.governance.canister_id,
        proposal_id,
    )
    .await
    .unwrap_err();

    // Step 3.2: One of the main things that clean_up_failed_register_extension
    // does is delete the extension canister itself, so let's make sure that
    // actually happened.
    let extension_canister_status_err = pocket_ic
        .canister_status(
            Principal::from(PrincipalId::from(extension_canister_id)),
            Some(Principal::from(PrincipalId::from(sns_root_canister_id))),
        )
        .await
        // When a canister is deleted, calling canister_status to fetch its status results in an Err.
        .unwrap_err();
    assert_eq!(
        extension_canister_status_err.error_code,
        pocket_ic::ErrorCode::CanisterNotFound
    );

    // Step 3.3: Another thing that clean_up_failed_register_extension is
    // supposed to do is "de-register" it from Root. That is, Root should not
    // consider the canister to be an extension of the SNS.
    let list_sns_canisters_response = agent
        .call(sns_root_canister_id, ListSnsCanistersRequest {})
        .await
        .unwrap();
    assert_eq!(
        list_sns_canisters_response
            .extensions
            .clone()
            .unwrap()
            .extension_canister_ids,
        vec![],
        "{list_sns_canisters_response:#?}",
    );
}

async fn do_test_treasury_manager() {
    let state_dir = TempDir::new().unwrap().path().to_path_buf();

    let World {
        pocket_ic,
        fiduciary_subnet_id,
        sns,
        sns_root_canister_id,
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
        neuron_id,
        sender,
        sns_ledger_canister_id,
        initial_icp_balance_e8s,
        initial_sns_balance_e8s,
    } = prepare_the_world(state_dir).await;

    let sns_token = Asset::Token {
        symbol: "Kanye".to_string(),
        ledger_canister_id: sns_ledger_canister_id.get().0,
        ledger_fee_decimals: Nat::from(SNS_FEE),
    };

    let icp_token = Asset::Token {
        symbol: "ICP".to_string(),
        ledger_canister_id: LEDGER_CANISTER_ID.get().0,
        ledger_fee_decimals: Nat::from(ICP_FEE),
    };

    let topup_treasury_allocation_icp_e8s = 50 * E8;
    // This cannot be 100, b/c there will be slightly less than 200 left in the treasury at the point where this is called.
    let topup_treasury_allocation_sns_e8s = 99 * E8;

    let extension_canister_id = {
        let agent = PocketIcAgent::new(&pocket_ic, sender);

        let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
            .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

        let wasm_path = PathBuf::from(wasm_path);

        let icp = Tokens::from_tokens(10).unwrap();
        cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

        let RegisterExtensionInfo {
            proposal_id,
            extension_canister_id,
            wasm_module_hash: _,
        } = register_extension::exec(
            RegisterExtensionArgs {
                sns_neuron_id: Some(ParsedSnsNeuron(neuron_id.clone())),
                sns_root_canister_id,
                subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
                wasm_path,
                proposal_url: Url::try_from("https://example.com").unwrap(),
                summary: "Register KongSwap Adaptor".to_string(),
                extension_init: make_deposit_allowances(
                    initial_treasury_allocation_icp_e8s,
                    initial_treasury_allocation_sns_e8s,
                ),
                network: None,
            },
            &agent,
        )
        .await
        .unwrap();

        for _ in 0..100 {
            pocket_ic.tick().await;
            pocket_ic.advance_time(Duration::from_secs(1)).await;
        }

        let proposal_id = proposal_id.unwrap();

        sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            proposal_id,
        )
        .await
        .unwrap();

        extension_canister_id.get()
    };

    let treasury_sns_account = sns_treasury_manager::Account {
        owner: sns.governance.canister_id.0,
        subaccount: Some(compute_distribution_subaccount_bytes(
            sns.governance.canister_id,
            TREASURY_SUBACCOUNT_NONCE,
        )),
    };

    let treasury_icp_account = sns_treasury_manager::Account {
        owner: sns.governance.canister_id.0,
        subaccount: None,
    };

    let empty_sns_balance_book = BalanceBook::empty()
        .with_treasury_owner(treasury_sns_account, "DAO Treasury".to_string())
        .with_treasury_manager(
            sns_treasury_manager::Account {
                owner: extension_canister_id.0,
                subaccount: None,
            },
            format!("KongSwapAdaptor({extension_canister_id})"),
        )
        .with_external_custodian(None, None)
        .with_fee_collector(None, None)
        .with_payees(None, None)
        .with_payers(None, None)
        .with_suspense(None);

    let empty_icp_balance_book = BalanceBook::empty()
        .with_treasury_owner(treasury_icp_account, "DAO Treasury".to_string())
        .with_treasury_manager(
            sns_treasury_manager::Account {
                owner: extension_canister_id.0,
                subaccount: None,
            },
            format!("KongSwapAdaptor({extension_canister_id})"),
        )
        .with_external_custodian(None, None)
        .with_fee_collector(None, None)
        .with_payees(None, None)
        .with_payers(None, None)
        .with_suspense(None);

    for _ in 0..100 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(1)).await;
    }

    validate_treasury_balances(
        "After registering KongSwapAdaptor",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s - (initial_treasury_allocation_icp_e8s + ICP_FEE),
        initial_sns_balance_e8s - (initial_treasury_allocation_sns_e8s + SNS_FEE),
    )
    .await
    .unwrap();

    {
        let request = BalancesRequest {};
        let response = pocket_ic
            .call(extension_canister_id, request)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            response.asset_to_balances,
            Some(btreemap! {
                sns_token.clone() => empty_sns_balance_book.clone()
                    .external_custodian(initial_treasury_allocation_sns_e8s - 3 * SNS_FEE)
                    .fee_collector(3 * SNS_FEE),
                icp_token.clone() => empty_icp_balance_book.clone()
                    .external_custodian(initial_treasury_allocation_icp_e8s - 3 * ICP_FEE)
                    .fee_collector(3 * ICP_FEE),
            }),
        );
    }

    // Wait for the KongSwap Adaptor to be ready for the next operation.
    //
    // This should be less than 1 hour to avoid hitting the next periodic task.
    for _ in 0..150 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(20)).await;
    }

    // Testing the top-up deposit operation.
    {
        let proposal = Proposal {
            title: "Test top-up deposit".to_string(),
            summary: "test".to_string(),
            url: "https://example.com".to_string(),
            action: Some(Action::ExecuteExtensionOperation(
                ExecuteExtensionOperation {
                    extension_canister_id: Some(extension_canister_id),
                    operation_name: Some("deposit".to_string()),
                    operation_arg: Some(ExtensionOperationArg {
                        value: make_deposit_allowances(
                            topup_treasury_allocation_icp_e8s,
                            topup_treasury_allocation_sns_e8s,
                        ),
                    }),
                },
            )),
        };

        let proposal_data = propose_and_wait(
            &pocket_ic,
            sns.governance.canister_id,
            sender,
            neuron_id.clone(),
            proposal.clone(),
        )
        .await
        .unwrap();

        assert_eq!(proposal_data.failure_reason, None);
        assert!(proposal_data.executed_timestamp_seconds > 0);
    }

    // Wait for the KongSwap Adaptor to be ready for the next operation.
    //
    // This should be less than 1 hour to avoid hitting the next periodic task.
    for _ in 0..100 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(35)).await;
    }

    // Testing the withdraw operation.
    {
        let proposal = Proposal {
            title: "Test withdraw".to_string(),
            summary: "test".to_string(),
            url: "https://example.com".to_string(),
            action: Some(Action::ExecuteExtensionOperation(
                ExecuteExtensionOperation {
                    extension_canister_id: Some(extension_canister_id),
                    operation_name: Some("withdraw".to_string()),
                    operation_arg: Some(ExtensionOperationArg { value: None }),
                },
            )),
        };

        let proposal_data = propose_and_wait(
            &pocket_ic,
            sns.governance.canister_id,
            sender,
            neuron_id.clone(),
            proposal.clone(),
        )
        .await
        .unwrap();

        assert_eq!(proposal_data.failure_reason, None);
        assert!(proposal_data.executed_timestamp_seconds > 0);

        {
            let request = AuditTrailRequest {};
            let response = pocket_ic
                .call(extension_canister_id, request)
                .await
                .unwrap();

            println!(">>> AuditTrail: {response:#?}");
        }

        // We have done 2 deposits and 1 withdrawal.
        // Each deposit has three fees:
        // - transfer fee from treasury owner to the treasury manager
        // - approval fee given from the treasury manager to the external custodian
        // - transfer fee from the treasury manager to the external custodian
        // Withdrawal has two fees:
        // - transfer fee from the external custodian to the treasury manager
        // - transfer fee from the treasury manager to the treasury owner
        let expected_sns_fee_collector = 8 * SNS_FEE;
        // Second deposit takes place with deposit ratio (SNS/ICP)
        // lower than the market ratio (SNS/ICP in the pool). Hence,
        // the excess amount of ICP is returned to the treasury owner.
        let expected_icp_fee_collector = 9 * ICP_FEE;

        let treasury_allocation_sns_e8s = initial_treasury_allocation_sns_e8s
            + topup_treasury_allocation_sns_e8s
            - expected_sns_fee_collector;
        let treasury_allocation_icp_e8s = initial_treasury_allocation_icp_e8s
            + topup_treasury_allocation_icp_e8s
            - expected_icp_fee_collector;

        let response = pocket_ic
            .call(extension_canister_id, BalancesRequest {})
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            response.asset_to_balances,
            Some(btreemap! {
                sns_token => empty_sns_balance_book
                    .clone()
                    .treasury_owner(treasury_allocation_sns_e8s)
                    .fee_collector(expected_sns_fee_collector),
                icp_token => empty_icp_balance_book
                    .clone()
                    .treasury_owner(treasury_allocation_icp_e8s)
                    .fee_collector(expected_icp_fee_collector),
            }),
        );
    };

    validate_treasury_balances(
        "After withdrawing.",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s - 11 * ICP_FEE,
        initial_sns_balance_e8s - 10 * SNS_FEE,
    )
    .await
    .unwrap();

    // let audit_trail = adaptor_canister_id.audit_trail();
    // println!("{:#?}", audit_trail.transactions());

    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 0).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 1).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 2).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 3).await;
    // dbg_print_block(&pocket_ic, sns_ledger_canister_id, 4).await;

    // panic!("  Directed by\nROBERT B. WEIDE.");
}

async fn run_existing_extension_wasm_rejected_test() {
    let state_dir = TempDir::new().unwrap().path().to_path_buf();

    let World {
        pocket_ic,
        fiduciary_subnet_id,
        sns,
        sns_root_canister_id,
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
        neuron_id,
        sender,

        // Unused in this scenario
        sns_ledger_canister_id: _,
        initial_icp_balance_e8s: _,
        initial_sns_balance_e8s: _,
    } = prepare_the_world(state_dir).await;

    let agent = PocketIcAgent::new(&pocket_ic, sender);

    let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
        .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

    let wasm_path = PathBuf::from(wasm_path);

    let icp = Tokens::from_tokens(10).unwrap();
    cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

    let proposal_url = Url::try_from("https://example.com").unwrap();
    let summary = "Register KongSwap Adaptor".to_string();
    let extension_init = make_deposit_allowances(
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
    );

    let RegisterExtensionInfo {
        proposal_id: _,
        extension_canister_id,
        wasm_module_hash,
    } = register_extension::exec(
        RegisterExtensionArgs {
            // Not setting the neuron is important, since we don't want to submit the proposal right away.
            sns_neuron_id: None,
            sns_root_canister_id,
            subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
            wasm_path,
            proposal_url: proposal_url.clone(),
            summary: summary.clone(),
            extension_init: extension_init.clone(),
            network: None,
        },
        &agent,
    )
    .await
    .unwrap();

    // Ensure there is some code already installed onto the extension canister before we try
    // to register it with the SNS.
    pocket_ic
        .install_canister(
            extension_canister_id.into(),
            get_universal_canister_wasm(),
            vec![],
            Some(sender.0),
        )
        .await;

    // Now, we're ready to submit the proposal to register an extension.
    let proposal = Proposal {
        title: format!(
            "Register SNS extension canister {}",
            extension_canister_id.get()
        ),
        summary,
        url: proposal_url.to_string(),
        action: Some(Action::RegisterExtension(RegisterExtension {
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                store_canister_id: Some(extension_canister_id.get()),
                // Simplification for this test: Assume the Wasm fits into one chunk.
                chunk_hashes_list: vec![wasm_module_hash.clone()],
                wasm_module_hash,
            }),
            extension_init: Some(ExtensionInit {
                value: extension_init,
            }),
        })),
    };

    let result: Result<SubmittedProposal, ProposalSubmissionError> = sns
        .governance
        .submit_proposal(&agent, neuron_id, proposal)
        .await
        .unwrap()
        .try_into();

    assert_eq!(
        result.unwrap_err(),
        ProposalSubmissionError::GovernanceError(GovernanceError {
            error_type: governance_error::ErrorType::InvalidProposal as i32,
            error_message: format!(
                "1 defects in Proposal:\nExtension canister {} already has code installed (module hash {}).",
                extension_canister_id,
                hex::encode(get_universal_canister_wasm_sha256())
            )
        })
    );
}

#[allow(unused)]
async fn dbg_print_block(pocket_ic: &PocketIc, ledger_canister_id: PrincipalId, block_index: u64) {
    let block = sns::ledger::get_all_blocks(pocket_ic, ledger_canister_id, block_index, 1).await;

    let Value::Map(block_details) = block.blocks[0].clone() else {
        panic!("Expected a block with details, got: {:?}", block.blocks[0]);
    };

    let Value::Map(tx_details) = block_details.get("tx").unwrap() else {
        panic!(
            "Expected a transaction in the block details, got: {:?}",
            block_details.get("tx")
        );
    };

    let from = tx_details.get("from");
    let to = tx_details.get("to");
    let spender = tx_details.get("spender");
    let amt = tx_details.get("amt").unwrap();
    let op = tx_details.get("op").unwrap();

    println!("SNS Ledger block {block_index} details.");
    println!("    amt = {amt:?}");
    println!("     op = {op:?}");
    println!("   from = {from:?}");
    println!("     to = {to:?}");
    println!("spender = {spender:?}");
}

async fn deploy_sns(pocket_ic: &PocketIc, with_mainnet_sns_canisters: bool) -> Sns {
    use ic_nervous_system_proto::pb::v1::{self as pb};

    add_wasms_to_sns_wasm(pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
    create_service_nervous_system.initial_token_distribution =
        Some(src::InitialTokenDistribution {
            developer_distribution: Some(src::DeveloperDistribution {
                developer_neurons: vec![src::NeuronDistribution {
                    controller: Some(PrincipalId::new_user_test_id(830947)),
                    dissolve_delay: Some(pb::Duration {
                        seconds: Some(ONE_MONTH_SECONDS * 6),
                    }),
                    memo: Some(763535),
                    stake: Some(pb::Tokens { e8s: Some(756575) }),
                    vesting_period: Some(pb::Duration { seconds: Some(0) }),
                }],
            }),
            treasury_distribution: Some(src::TreasuryDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(400 * E8),
                }),
            }),
            swap_distribution: Some(src::SwapDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(1_840_880_000),
                }),
            }),
        });

    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();

    let sns_instance_label = "1";
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    sns::swap::await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();
    sns::swap::smoke_test_participate_and_finalize(
        pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    sns
}

async fn validate_treasury_balances(
    lebel: &str,
    sns: &Sns,
    pocket_ic: &PocketIc,
    icp_balance_e8s: u64,
    sns_balance_e8s: u64,
) -> Result<(), String> {
    let sns_treasury_subaccount = compute_distribution_subaccount_bytes(
        sns.governance.canister_id,
        TREASURY_SUBACCOUNT_NONCE,
    );

    let owner = sns.governance.canister_id.0;

    for (token_name, ledger_canister_id, subaccount, expected_balance_e8s) in [
        ("ICP", LEDGER_CANISTER_ID.get(), None, icp_balance_e8s),
        (
            "SNS",
            sns.ledger.canister_id,
            Some(sns_treasury_subaccount),
            sns_balance_e8s,
        ),
    ] {
        let account = Account { owner, subaccount };

        let observed_balance_e8s =
            sns::ledger::icrc1_balance_of(pocket_ic, ledger_canister_id, account).await;

        let expected_balance_e8s = Nat::from(expected_balance_e8s);

        if observed_balance_e8s != expected_balance_e8s {
            return Err(format!(
                "[{lebel}] Expected treasury {token_name} balance of {expected_balance_e8s}, got {observed_balance_e8s}."
            ));
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_upgrade_extension() {
    let state_dir = TempDir::new().unwrap().path().to_path_buf();

    let World {
        pocket_ic,
        fiduciary_subnet_id,
        sns,
        sns_root_canister_id,
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
        neuron_id,
        sender,

        // Unused in this scenario
        sns_ledger_canister_id: _,
        initial_icp_balance_e8s: _,
        initial_sns_balance_e8s: _,
    } = prepare_the_world(state_dir).await;

    let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
        .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

    let wasm_path = PathBuf::from(wasm_path);
    let adaptor_v1 = Wasm::from_file(&wasm_path);
    println!("Kong V1 hash?: {:?}", adaptor_v1.sha256_hash());

    // Step 6: Register the extension via RegisterExtension proposal
    let extension_canister_id = {
        let agent = PocketIcAgent::new(&pocket_ic, sender);

        let icp = Tokens::from_tokens(10).unwrap();
        cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

        let RegisterExtensionInfo {
            proposal_id,
            extension_canister_id,
            wasm_module_hash: _,
        } = register_extension::exec(
            RegisterExtensionArgs {
                sns_neuron_id: Some(ParsedSnsNeuron(neuron_id.clone())),
                sns_root_canister_id,
                subnet_id: Some(PrincipalId(fiduciary_subnet_id)),
                wasm_path: wasm_path.clone(),
                proposal_url: Url::try_from("https://example.com").unwrap(),
                summary: "Register KongSwap Adaptor".to_string(),
                extension_init: make_deposit_allowances(
                    initial_treasury_allocation_icp_e8s,
                    initial_treasury_allocation_sns_e8s,
                ),
                network: None,
            },
            &agent,
        )
        .await
        .unwrap();

        let proposal_id = proposal_id.unwrap();

        let _proposal_data = sns::governance::wait_for_proposal_execution(
            &pocket_ic,
            sns.governance.canister_id,
            proposal_id,
        )
        .await
        .unwrap();

        extension_canister_id.get()
    };
    // Wait for install and registration
    for _ in 0..100 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(100)).await;
    }

    let extension_canister_status = pocket_ic
        .canister_status(extension_canister_id.0, Some(sns_root_canister_id.get().0))
        .await
        .unwrap();
    assert_eq!(
        extension_canister_status.module_hash,
        Some(adaptor_v1.sha256_hash().to_vec())
    );

    // Step 7: Create v2 KongSwap WASM with modified metadata
    let adaptor_v2 = {
        let wasm_bytes = std::fs::read(&wasm_path).expect("Failed to read WASM file");

        let wasm_bytes = modify_wasm_bytes(&wasm_bytes, 1);

        Wasm::from_bytes(wasm_bytes)
    };

    println!("🗳️  Submitting UpgradeExtension proposal...");

    // Step 8: Create UpgradeExtension proposal

    let upgrade_extension_proposal = Proposal {
        title: "Upgrade KongSwap Extension to v2".to_string(),
        url: "https://example.com/upgrade-kongswap".to_string(),
        summary: "Upgrading KongSwap extension to version 2 with enhanced features".to_string(),
        action: Some(Action::UpgradeExtension(UpgradeExtension {
            extension_canister_id: Some(extension_canister_id),
            canister_upgrade_arg: Some(ExtensionUpgradeArg {
                value: None, // Treasury manager currently has no upgrade args
            }),
            wasm: Some(ApiWasm::Bytes(adaptor_v2.clone().bytes())),
        })),
    };

    let _proposal_data = propose_and_wait(
        &pocket_ic,
        sns.governance.canister_id,
        sender,
        neuron_id,
        upgrade_extension_proposal,
    )
    .await
    .expect("Failed to propose UpgradeExtension");

    // Wait a bit for the upgrade to complete
    for _ in 0..10 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(1)).await;
    }

    let extension_canister_status = pocket_ic
        .canister_status(extension_canister_id.0, Some(sns_root_canister_id.get().0))
        .await
        .unwrap();
    assert_eq!(
        extension_canister_status.module_hash,
        Some(adaptor_v2.sha256_hash().to_vec())
    );
}

fn make_deposit_allowances(
    treasury_allocation_icp_e8s: u64,
    treasury_allocation_sns_e8s: u64,
) -> Option<PreciseValue> {
    Some(PreciseValue::Map(btreemap! {
        "treasury_allocation_icp_e8s".to_string() => PreciseValue::Nat(treasury_allocation_icp_e8s),
        "treasury_allocation_sns_e8s".to_string() => PreciseValue::Nat(treasury_allocation_sns_e8s),
    }))
}

struct World {
    pocket_ic: PocketIc,
    fiduciary_subnet_id: Principal,
    sns: Sns,
    sns_ledger_canister_id: CanisterId,
    sns_root_canister_id: CanisterId,
    initial_icp_balance_e8s: u64,
    initial_sns_balance_e8s: u64,
    initial_treasury_allocation_icp_e8s: u64,
    initial_treasury_allocation_sns_e8s: u64,
    neuron_id: NeuronId,
    sender: PrincipalId,
}

async fn prepare_the_world(state_dir: PathBuf) -> World {
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let _sns_subnet_id = topology.get_sns().unwrap();

    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();

    println!(">>> Fiduciary subnet ID: {fiduciary_subnet_id}");

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    {
        let registry_proto_path = state_dir.join("registry.proto");
        let initial_mutations = load_registry_mutations(registry_proto_path);

        let mut nns_installer = NnsInstaller::default();
        nns_installer
            .with_current_nns_canister_versions()
            .with_test_governance_canister()
            .with_cycles_minting_canister()
            .with_cycles_ledger()
            .with_custom_registry_mutations(vec![initial_mutations]);
        nns_installer.install(&pocket_ic).await;
    }

    add_fiduciary_subnet_type(&pocket_ic).await;
    add_fiduciary_subnet_to_cmc(
        &pocket_ic,
        SubnetId::from(PrincipalId::from(fiduciary_subnet_id)),
    )
    .await;

    let sns = deploy_sns(&pocket_ic, false).await;

    setup_allowed_extension_specs(&pocket_ic, sns.governance.canister_id).await;

    // Install KongSwap
    let _kong_backend_canister_id = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");

        let kong_backend_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![PrincipalId::new_user_test_id(42)];

        // Canister ID from the mainnet.
        // See https://dashboard.internetcomputer.org/canister/2ipq2-uqaaa-aaaar-qailq-cai
        let canister_id = CanisterId::try_from_principal_id(
            PrincipalId::from_str("2ipq2-uqaaa-aaaar-qailq-cai").unwrap(),
        )
        .unwrap();

        install_canister_with_controllers(
            &pocket_ic,
            "KongSwap Backend Canister",
            canister_id,
            vec![],
            kong_backend_wasm,
            controllers,
        )
        .await;

        canister_id
    };

    let sns_ledger_canister_id = CanisterId::try_from_principal_id(sns.ledger.canister_id).unwrap();
    let sns_root_canister_id = CanisterId::try_from_principal_id(sns.root.canister_id).unwrap();

    // These numbers just happen to be what is going on in deploy_sns() above.  They're not particularly
    // special in any way.
    let initial_icp_balance_e8s = 650_000 * E8 - ICP_FEE;
    let initial_sns_balance_e8s = 400 * E8;

    validate_treasury_balances(
        "Before registering KongSwapAdaptor",
        &sns,
        &pocket_ic,
        initial_icp_balance_e8s,
        initial_sns_balance_e8s,
    )
    .await
    .unwrap();

    let initial_treasury_allocation_icp_e8s = 100 * E8;
    let initial_treasury_allocation_sns_e8s = 200 * E8;

    let (neuron_id, sender) = sns::governance::find_neuron_with_majority_voting_power(
        &pocket_ic,
        sns.governance.canister_id,
    )
    .await
    .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    World {
        pocket_ic,
        fiduciary_subnet_id,
        sns,
        sns_ledger_canister_id,
        sns_root_canister_id,
        initial_icp_balance_e8s,
        initial_sns_balance_e8s,
        initial_treasury_allocation_icp_e8s,
        initial_treasury_allocation_sns_e8s,
        neuron_id,
        sender,
    }
}

/// Add the "fiduciary" subnet type to CMC by impersonating Governance
async fn add_fiduciary_subnet_type(pocket_ic: &PocketIc) {
    #[derive(candid::CandidType)]
    enum UpdateSubnetTypeArgs {
        Add(String),
    }

    let args = UpdateSubnetTypeArgs::Add("fiduciary".to_string());
    let payload = Encode!(&args).expect("Failed to encode UpdateSubnetTypeArgs");

    let result = pocket_ic
        .update_call(
            CYCLES_MINTING_CANISTER_ID.get().into(),
            GOVERNANCE_CANISTER_ID.get().into(),
            "update_subnet_type",
            payload,
        )
        .await;

    match result {
        Ok(_) => println!("Successfully added fiduciary subnet type to CMC"),
        Err(e) => panic!("Failed to add fiduciary subnet type to CMC: {e:?}"),
    }
}

/// Register the fiduciary subnet with the "fiduciary" type in CMC by impersonating Governance
async fn add_fiduciary_subnet_to_cmc(pocket_ic: &PocketIc, fiduciary_subnet_id: SubnetId) {
    #[derive(candid::CandidType)]
    struct SubnetListWithType {
        subnets: Vec<SubnetId>,
        subnet_type: String,
    }

    #[derive(candid::CandidType)]
    enum ChangeSubnetTypeAssignmentArgs {
        Add(SubnetListWithType),
    }

    let args = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
        subnets: vec![fiduciary_subnet_id],
        subnet_type: "fiduciary".to_string(),
    });

    let payload = Encode!(&args).expect("Failed to encode ChangeSubnetTypeAssignmentArgs");

    let result = pocket_ic
        .update_call(
            CYCLES_MINTING_CANISTER_ID.get().into(),
            GOVERNANCE_CANISTER_ID.get().into(),
            "change_subnet_type_assignment",
            payload,
        )
        .await;

    match result {
        Ok(_) => {
            println!("Successfully registered fiduciary subnet {fiduciary_subnet_id} with CMC")
        }
        Err(e) => panic!("Failed to register fiduciary subnet with CMC: {e:?}"),
    }
}

async fn add_allowed_extension(
    pocket_ic: &PocketIc,
    sns_governance_canister_id: PrincipalId,
    hash: [u8; 32],
    pb_extension: ExtensionSpec,
) {
    println!("We are making the add_allowed_extension call...");
    let payload = Encode!(&AddAllowedExtensionRequest {
        wasm_hash: hash.to_vec(),
        spec: Some(pb_extension)
    })
    .unwrap();

    pocket_ic
        .update_call(
            sns_governance_canister_id.0,
            PrincipalId::new_anonymous().0,
            "add_allowed_extension",
            payload,
        )
        .await
        .unwrap();
}

async fn setup_allowed_extension_specs(
    pocket_ic: &PocketIc,
    sns_governance_canister_id: PrincipalId,
) {
    let wasm_path = std::env::var("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH")
        .expect("KONGSWAP_ADAPTOR_CANISTER_WASM_PATH must be set.");

    let kong_backend_wasm = Wasm::from_file(wasm_path);

    let v1_hash = kong_backend_wasm.sha256_hash();

    let v2_hash = Wasm::from_bytes(modify_wasm_bytes(&kong_backend_wasm.bytes(), 1)).sha256_hash();

    let spec_v1 = ExtensionSpec {
        name: Some("KongSwap Treasury Manager".to_string()),
        version: Some(1),
        topic: Some(6),          // TreasuryAssetManagement
        extension_type: Some(1), // TreasuryManager
    };
    let spec_v2 = ExtensionSpec {
        name: Some("KongSwap Treasury Manager".to_string()),
        version: Some(2),        // Version Bump
        topic: Some(6),          // TreasuryAssetManagement
        extension_type: Some(1), // TreasuryManager
    };

    add_allowed_extension(pocket_ic, sns_governance_canister_id, v1_hash, spec_v1).await;
    add_allowed_extension(pocket_ic, sns_governance_canister_id, v2_hash, spec_v2).await;
}
