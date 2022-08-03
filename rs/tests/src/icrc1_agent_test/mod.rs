use std::convert::TryFrom;

use candid::{Encode, Nat, Principal};
use canister_test::{Canister, PrincipalId, RemoteTestRuntime, Runtime};
use ic_canister_client::{Agent, Sender};
use ic_fondue::ic_manager::IcHandle;
use ic_icrc1::Account;
use ic_icrc1_agent::{CallMode, Icrc1Agent, TransferArg, Value};
use ic_icrc1_ledger::InitArgs;
use ic_nns_test_utils::itest_helpers::install_rust_canister;
use ic_registry_subnet_type::SubnetType;
use ledger_canister::ArchiveOptions;

use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        pot_dsl::{par, pot, t, Pot},
    },
    nns::first_root_endpoint,
    util::assert_create_agent,
};

pub fn icrc1_agent_test_pot() -> Pot {
    pot(
        "icrc1_agent_test_pot",
        config(),
        par(vec![t("icrc1_agent_test", test)]),
    )
}

fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::fast_single_node(SubnetType::Application))
}

fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = first_root_endpoint(&handle);
        endpoint.assert_ready(ctx).await;
        let runtime = Runtime::Remote(RemoteTestRuntime {
            agent: Agent::new(
                endpoint.url.clone(),
                Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
            ),
        });

        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let minting_user = PrincipalId::new_user_test_id(100);
        let user1 = PrincipalId::try_from(agent.get_principal().unwrap().as_ref()).unwrap();
        let user2 = PrincipalId::new_user_test_id(102);
        let account1 = Account {
            of: user1,
            subaccount: None,
        };
        let account2 = Account {
            of: user2,
            subaccount: None,
        };
        let minting_account = Account {
            of: minting_user,
            subaccount: None,
        };
        let mut ledger = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Unable to create canister");
        // let mut ledger = Canister::new(&runtime, ledger_canister_id);
        let init_args = InitArgs {
            minting_account,
            initial_balances: vec![(account1.clone(), 1_000_000_000)],
            transfer_fee: 1_000,
            token_name: "Example Token".to_string(),
            token_symbol: "XTK".to_string(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: 1000,
                num_blocks_to_archive: 1000,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: minting_user,
                cycles_for_archive_creation: None,
            },
        };
        install_icrc1_ledger(&mut ledger, &init_args).await;

        /////////////
        // test

        let agent = Icrc1Agent {
            agent: assert_create_agent(endpoint.url.as_str()).await,
            ledger_canister_id: Principal::try_from_slice(ledger.canister_id().as_ref()).unwrap(),
        };

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
            Nat::from(1_000_000_000u64),
            agent.total_supply(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(1_000_000_000u64),
            agent.total_supply(CallMode::Update).await.unwrap()
        );

        // fee
        assert_eq!(
            Nat::from(init_args.transfer_fee),
            agent.fee(CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(init_args.transfer_fee),
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
            Value::entry("icrc1:fee", init_args.transfer_fee),
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
            agent
                .balance_of(account1.clone(), CallMode::Query)
                .await
                .unwrap()
        );
        assert_eq!(
            Nat::from(1_000_000_000u64),
            agent
                .balance_of(account1.clone(), CallMode::Update)
                .await
                .unwrap()
        );

        // transfer
        let amount = 10_000_000u64;
        let _block = agent
            .transfer(TransferArg {
                from_subaccount: None,
                to_principal: user2,
                to_subaccount: None,
                fee: None,
                created_at_time: None,
                amount: Nat::from(amount),
                memo: None,
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            Nat::from(1_000_000_000u64 - amount - init_args.transfer_fee),
            agent.balance_of(account1, CallMode::Query).await.unwrap()
        );
        assert_eq!(
            Nat::from(amount),
            agent.balance_of(account2, CallMode::Query).await.unwrap()
        );
    });
}

pub async fn install_icrc1_ledger<'a>(canister: &mut Canister<'a>, args: &InitArgs) {
    install_rust_canister(
        canister,
        "rosetta-api/icrc1/ledger",
        "ic-icrc1-ledger",
        &[],
        Some(Encode!(&args).unwrap()),
    )
    .await
}
