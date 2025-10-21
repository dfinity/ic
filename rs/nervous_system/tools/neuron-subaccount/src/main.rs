use clap::Parser;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Subaccount};

/// If you know the controller and memo of a neuron, this will tell you the
/// neuron's subaccount/the NNS Governance's account where the neuron's balance
/// is kept.
#[derive(Debug, Parser)]
struct Argv {
    #[clap(long)]
    controller: PrincipalId,

    #[clap(long)]
    memo: u64,
}

fn main() {
    let argv = Argv::parse();

    let subaccount: Subaccount = compute_neuron_staking_subaccount(argv.controller, argv.memo);
    println!("Subaccount: {subaccount}");

    let governance_account =
        AccountIdentifier::new(PrincipalId::from(GOVERNANCE_CANISTER_ID), Some(subaccount))
            .to_hex();
    println!("Governance Account: {governance_account}");
}
