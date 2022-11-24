pub(crate) mod accounts;
pub(crate) mod transactions;

use crate::{get_ledger_principal, next_u64};
use candid::{Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::management_canister::main::{
    CanisterIdRecord, CanisterInstallMode, CreateCanisterArgument, InstallCodeArgument, WasmModule,
};
use ic_icrc1::{endpoints::TransferArg, Account};
use ic_icrc1_benchmark_worker::InitArgs;
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use ic_ledger_core::Tokens;

pub(crate) const ICP_E8S: Tokens = Tokens::from_e8s(100_000_000);

fn get_ledger_client() -> ICRC1Client<CdkRuntime> {
    let ledger_canister_id = Principal::from(get_ledger_principal());
    ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    }
}

/// Create some worker canisters.
async fn create_workers(nb_workers: u32) -> Vec<Principal> {
    let mut workers = vec![];
    for i in 0..nb_workers {
        let worker_id =
            ic_cdk::api::management_canister::main::create_canister(CreateCanisterArgument {
                settings: None,
            })
            .await
            .expect("Error while creating worker canister.")
            .0
            .canister_id;
        ic_cdk::println!(
            "Created worker canister [{}/{}] {}",
            i + 1,
            nb_workers,
            worker_id
        );
        workers.push(worker_id);
    }
    workers
}

/// Transfer cycles from caller to some canisters.
async fn transfer_cycles_to_canisters(cycles: u128, canisters: Vec<Principal>) {
    for canister_id in canisters.iter() {
        ic_cdk::println!("Transferring cycles to worker canister {}...", canister_id);
        let _res = ic_cdk::api::management_canister::main::deposit_cycles(
            CanisterIdRecord {
                canister_id: *canister_id,
            },
            cycles,
        )
        .await;
    }
}

/// Install wasm code on all provided canisters.
async fn install_code_on_canisters(wasm: WasmModule, canisters: Vec<Principal>) {
    for canister_id in canisters.iter() {
        ic_cdk::println!(
            "Installing worker code on worker canister {}...",
            canister_id
        );
        let arg = InitArgs {
            ledger_id: CanisterId::new(get_ledger_principal()).unwrap(),
            rand_seed: Nat::from(next_u64()),
        };
        let arg = &Encode!(&arg).expect("Error while encoding arg");
        ic_cdk::api::management_canister::main::install_code(InstallCodeArgument {
            mode: CanisterInstallMode::Install,
            canister_id: *canister_id,
            wasm_module: wasm.clone(),
            arg: arg.to_vec(),
        })
        .await
        .expect("Error while installing worker code.");
    }
}

async fn transfer_tokens_to_canisters(amount: u64, canisters: Vec<Principal>) {
    let client = get_ledger_client();
    for canister_id in canisters.iter() {
        ic_cdk::println!("Transferring tokens to worker canister {}...", canister_id);
        let worker = PrincipalId::from(*canister_id);
        let _block_index = client
            .transfer(TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: worker,
                    subaccount: None,
                },
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(amount),
            })
            .await
            .expect("Error while calling transfer")
            .expect("Error while transferring tokens to worker");
    }
}

/// Perform a canister upgrade to verify its state preservation.
async fn verify_canister_upgrade(canister_id: Principal, wasm: WasmModule) -> Result<(), ()> {
    let result =
        ic_cdk::api::management_canister::main::stop_canister(CanisterIdRecord { canister_id })
            .await;
    if let Err((code, msg)) = result {
        ic_cdk::eprintln!("Error while stopping canister: [{:?}] {}", code, msg);
        return Err(());
    }
    let result = ic_cdk::api::management_canister::main::install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Upgrade,
        canister_id,
        wasm_module: wasm.clone(),
        arg: vec![],
    })
    .await;
    ic_cdk::println!("Upgrade result: {:?}", result);
    if let Err((code, msg)) = result {
        ic_cdk::eprintln!("Error while upgrading canister: [{:?}] {}", code, msg);
        return Err(());
    }
    let result =
        ic_cdk::api::management_canister::main::start_canister(CanisterIdRecord { canister_id })
            .await;
    if let Err((code, msg)) = result {
        ic_cdk::eprintln!("Error while starting canister: [{:?}] {}", code, msg);
        return Err(());
    }
    Ok(())
}
