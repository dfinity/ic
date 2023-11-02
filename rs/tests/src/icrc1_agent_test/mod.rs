use std::convert::TryFrom;

use crate::util::{agent_with_identity, random_ed25519_identity};
use assert_matches::assert_matches;
use candid::{Encode, Nat, Principal};
use canister_test::{Canister, PrincipalId};
use ic_crypto_tree_hash::{LookupStatus, MixedHashTree};
use ic_icrc1_ledger::{FeatureFlags, InitArgsBuilder, LedgerArgument};
use ic_nns_test_utils::itest_helpers::install_rust_canister_from_path;
use ic_registry_subnet_type::SubnetType;
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value, icrc3::blocks::GetBlocksRequest,
};

use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url},
};

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    block_on(async move {
        let minting_user = PrincipalId::new_user_test_id(100);
        let user1 = PrincipalId::try_from(nns_agent.get_principal().unwrap().as_ref()).unwrap();
        let user2 = PrincipalId::new_user_test_id(102);
        let user3 = PrincipalId::new_user_test_id(270);

        let mut ledger = nns_runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Unable to create canister");

        let agent = Icrc1Agent {
            agent: assert_create_agent(nns_node.get_public_url().as_str()).await,
            ledger_canister_id: Principal::try_from_slice(ledger.canister_id().as_ref()).unwrap(),
        };

        let other_agent = Icrc1Agent {
            agent: agent_with_identity(
                nns_node.get_public_url().as_str(),
                random_ed25519_identity(),
            )
            .await
            .unwrap(),
            ledger_canister_id: Principal::try_from_slice(ledger.canister_id().as_ref()).unwrap(),
        };

        let other_agent_principal = other_agent.agent.get_principal().unwrap();

        let account1 = Account {
            owner: user1.0,
            subaccount: None,
        };
        let account2 = Account {
            owner: user2.0,
            subaccount: None,
        };
        let account3 = Account {
            owner: user3.0,
            subaccount: None,
        };
        let minting_account = Account {
            owner: minting_user.0,
            subaccount: None,
        };

        let init_args = InitArgsBuilder::for_tests()
            .with_minting_account(minting_account)
            .with_initial_balance(account1, 1_000_000_000u64)
            .with_transfer_fee(1_000)
            .with_feature_flags(FeatureFlags { icrc2: true })
            .build();
        install_icrc1_ledger(&env, &mut ledger, &LedgerArgument::Init(init_args.clone())).await;

        // name
        assert_eq!(
            init_args.token_name,
            agent.name(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            init_args.token_name,
            agent.name(CallMode::Update).await.unwrap()
        );

        // symbol
        assert_eq!(
            init_args.token_symbol,
            agent.symbol(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            init_args.token_symbol,
            agent.symbol(CallMode::Update).await.unwrap()
        );

        // decimal
        assert_eq!(
            ic_ledger_core::tokens::DECIMAL_PLACES as u8,
            agent.decimals(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            ic_ledger_core::tokens::DECIMAL_PLACES as u8,
            agent.decimals(CallMode::Update).await.unwrap()
        );

        // total_supply
        assert_eq!(
            Nat::from(1_000_000_000_u64),
            agent.total_supply(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(1_000_000_000_u64),
            agent.total_supply(CallMode::Update).await.unwrap()
        );

        // fee
        assert_eq!(
            init_args.transfer_fee,
            agent.fee(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            init_args.transfer_fee,
            agent.fee(CallMode::Update).await.unwrap()
        );

        // minting account
        assert_eq!(
            Some(&init_args.minting_account),
            agent
                .minting_account(CallMode::Query)
                .await
                .unwrap()
                .as_ref()
        );
        assert_eq!(
            Some(&init_args.minting_account),
            agent
                .minting_account(CallMode::Update)
                .await
                .unwrap()
                .as_ref()
        );

        // metadata
        let expected_metadata = vec![
            Value::entry(
                "icrc1:decimals",
                ic_ledger_core::tokens::DECIMAL_PLACES as u64,
            ),
            Value::entry("icrc1:name", init_args.token_name),
            Value::entry("icrc1:symbol", init_args.token_symbol),
            Value::entry("icrc1:fee", init_args.transfer_fee.clone()),
            Value::entry("icrc1:max_memo_length", 32u64),
        ];
        assert_eq!(
            expected_metadata,
            agent.metadata(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            expected_metadata,
            agent.metadata(CallMode::Update).await.unwrap()
        );
        // balance_of
        assert_eq!(
            Nat::from(1_000_000_000u64),
            agent.balance_of(account1, CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(1_000_000_000u64),
            agent.balance_of(account1, CallMode::Update).await.unwrap()
        );

        // transfer
        let amount = 10_000_000u64;
        let _block = agent
            .transfer(TransferArg {
                from_subaccount: None,
                to: account2,
                fee: None,
                created_at_time: None,
                amount: Nat::from(amount),
                memo: None,
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            Nat::from(1_000_000_000u64 - amount) - init_args.transfer_fee,
            agent.balance_of(account1, CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(amount),
            agent.balance_of(account2, CallMode::Query).await.unwrap()
        );

        let blocks_request = GetBlocksRequest {
            start: Nat::from(0),
            length: Nat::from(10),
        };
        let blocks_response = agent.get_blocks(blocks_request).await.unwrap();
        assert_eq!(Nat::from(0), blocks_response.first_index);
        assert_eq!(Nat::from(2), blocks_response.chain_length);

        let data_certificate = agent.get_data_certificate().await.unwrap();
        assert!(data_certificate.certificate.is_some());

        use LookupStatus::Found;
        let hash_tree: MixedHashTree = serde_cbor::from_slice(&data_certificate.hash_tree).unwrap();

        assert_eq!(
            hash_tree.lookup(&[b"last_block_index"]),
            Found(&mleaf((1_u64).to_be_bytes()))
        );

        assert_eq!(
            hash_tree.lookup(&[b"tip_hash"]),
            Found(&mleaf(blocks_response.blocks[1].hash()))
        );

        let cert = serde_cbor::from_slice(&data_certificate.certificate.unwrap()).unwrap();
        assert_matches!(
            agent.verify_root_hash(&cert, &hash_tree.digest().0).await,
            Ok(_)
        );

        let _block = agent
            .approve(ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: other_agent_principal,
                    subaccount: None,
                },
                amount: Nat::from(u64::MAX),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .await
            .unwrap()
            .unwrap();
        const TRANSFER_FROM_AMOUNT: u64 = 10_000;
        let _block = other_agent
            .transfer_from(TransferFromArgs {
                spender_subaccount: None,
                from: account1,
                to: account3,
                amount: Nat::from(TRANSFER_FROM_AMOUNT),
                fee: None,
                memo: None,
                created_at_time: None,
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            Nat::from(TRANSFER_FROM_AMOUNT),
            agent.balance_of(account3, CallMode::Query).await.unwrap()
        );
    });
}

fn mleaf<B: AsRef<[u8]>>(blob: B) -> MixedHashTree {
    MixedHashTree::Leaf(blob.as_ref().to_vec())
}

pub async fn install_icrc1_ledger<'a>(
    env: &TestEnv,
    canister: &mut Canister<'a>,
    args: &LedgerArgument,
) {
    install_rust_canister_from_path(
        canister,
        env.get_dependency_path("rs/rosetta-api/icrc1/ledger/ledger_canister.wasm"),
        Some(Encode!(&args).unwrap()),
    )
    .await
}
