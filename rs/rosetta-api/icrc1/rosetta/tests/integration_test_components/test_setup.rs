use crate::common::local_replica;

#[tokio::test]
async fn smoke_test() {
    // This is how you create and start a new local replica
    let replica_context = local_replica::start_new_local_replica().await;

    // To deploy the icrc ledger canister you can either deploy it with default arguments or with custom argument (local_replica.deploy_icrc_ledger_with_custom_args())
    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;

    // The result is the canister id of the icrc ledger
    println!(
        "The canister id of the icrc ledger is: {:?}",
        icrc_ledger_canister_id
    )
}
