use candid::Nat;
use candid_utils::wasm::{InMemoryWasm, Wasm};
use cycles_minting_canister::{CanisterSettingsArgs, SubnetSelection};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_base_types::SubnetId;
use ic_management_canister_types::BoundedVec;
use ic_nervous_system_agent::ii::cycles_ledger as production_cycles_ledger;
use ic_nervous_system_agent::ii::store::withdraw_cycles;
use ic_nervous_system_agent::management_canister as production_management_canister;
use ic_nervous_system_agent::management_canister::requests::Mode;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    cycles_ledger, load_registry_mutations, NnsInstaller,
};
use ic_sns_cli::upgrade_sns_controlled_canister::STORE_CANISTER_INITIAL_CYCLES_BALANCE;
use icp_ledger::Tokens;
use pocket_ic::PocketIcBuilder;
use store_canister_embedder::{StoreCanisterInitArgs, STORE_CANISTER_WASM};
use tempfile::TempDir;

const CYCLES_LEDGER_FEE: u128 = 100_000_000;
const RESERVED_CYCLES: u128 = 140_000_000_000;

#[tokio::test]
async fn store_canister_integration() {
    // 1. Prepare the world
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // 1.1. Install the NNS canisters.
    {
        let registry_proto_path = state_dir.join("registry.proto");
        let initial_mutations = load_registry_mutations(registry_proto_path);

        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_current_nns_canister_versions();
        nns_installer.with_cycles_minting_canister();
        nns_installer.with_cycles_ledger();
        nns_installer.with_custom_registry_mutations(vec![initial_mutations]);
        nns_installer.install(&pocket_ic).await;
    }

    // 1.2. Prepare a user with 10 ICP worth of cycles in the Cycles Ledger account.
    let sender = PrincipalId::new_user_test_id(42);
    let icp = Tokens::from_tokens(10).unwrap();
    cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;
    let pocket_ic_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: sender.into(),
    };

    // 1.3. Install the store canister on an app subnet.
    let (store_wasm, store_arg) = {
        let store_wasm = InMemoryWasm::try_from(STORE_CANISTER_WASM).unwrap();
        let store_arg = StoreCanisterInitArgs {
            authorized_principal: sender,
        }
        .render();
        let store_arg = store_wasm.encode_candid_args(&Some(store_arg)).unwrap();
        (store_wasm, store_arg)
    };

    // 1.4. Deploy the store canister.
    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let subnet_selection = Some(SubnetSelection::Subnet {
        subnet: SubnetId::from(PrincipalId(app_subnet)),
    });
    let store_canister_id = production_cycles_ledger::create_canister(
        &pocket_ic_agent,
        STORE_CANISTER_INITIAL_CYCLES_BALANCE,
        subnet_selection,
        Some(CanisterSettingsArgs {
            controllers: Some(BoundedVec::new(vec![sender])),
            freezing_threshold: Some(Nat::from(0_u128)),
            reserved_cycles_limit: Some(Nat::from(0_u128)),
            ..Default::default()
        }),
    )
    .await
    .map(|create_canister_success| {
        CanisterId::unchecked_from_principal(create_canister_success.canister_id)
    })
    .unwrap();
    production_management_canister::install_code(
        &pocket_ic_agent,
        store_canister_id,
        Mode::Install,
        store_wasm.bytes().to_vec(),
        store_arg,
        None,
    )
    .await
    .unwrap();

    // 2. Run code under test.

    // 2.1. Fetch the relevant bits from the pre-state.
    let initial_store_cycles_balance = pocket_ic
        .canister_status(store_canister_id.into(), Some(sender.into()))
        .await
        .unwrap()
        .cycles;
    let initial_cycles_balance = ic_nervous_system_agent::ii::cycles_ledger::icrc1_balance_of(
        &pocket_ic_agent,
        sender,
        None,
    )
    .await;
    // 2.1.1. Smoke test.
    assert!(initial_store_cycles_balance.clone() > RESERVED_CYCLES);

    // 2.2. Trigger the ultimate state transition.
    let amount_cycles_withdrawn =
        withdraw_cycles(&pocket_ic_agent, store_canister_id, sender).await;

    // 2.3. Fetch the relevant bits from the post-state.
    let final_store_cycles_balance = pocket_ic
        .canister_status(store_canister_id.into(), Some(sender.into()))
        .await
        .unwrap()
        .cycles;
    let final_cycles_balance = ic_nervous_system_agent::ii::cycles_ledger::icrc1_balance_of(
        &pocket_ic_agent,
        sender,
        None,
    )
    .await;

    // 3. Inspect the results.
    let fee = Nat::from(CYCLES_LEDGER_FEE);
    assert_eq!(
        final_cycles_balance,
        initial_cycles_balance + amount_cycles_withdrawn.clone() - fee.clone()
    );
    assert!(amount_cycles_withdrawn > fee);

    assert!(final_store_cycles_balance < Nat::from(RESERVED_CYCLES));
    assert!(
        initial_store_cycles_balance.clone() - final_store_cycles_balance.clone() > Nat::from(RESERVED_CYCLES),
        "initial_store_cycles_balance ({}) - final_store_cycles_balance ({}) should be > RESERVED_CYCLES ({})",
        initial_store_cycles_balance, final_store_cycles_balance, RESERVED_CYCLES,
    );
}
