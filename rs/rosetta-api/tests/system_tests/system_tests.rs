use common::system_test_environment::RosettaTestingEnvironment;
use tokio::runtime::Runtime;

mod common;
mod test_cases;

#[test]
fn smoke_test() {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let res = rosetta_testing_environment
            .rosetta_client
            .network_list()
            .await
            .unwrap();
        assert_eq!(res.network_identifiers.len(), 1);
    });
}

#[test]
fn test_cc() {
    println!(
        "Acc: {:?}",
        icp_ledger::AccountIdentifier::new(
            ic_types::PrincipalId(
                candid::Principal::from_text(
                    "iowfl-yzooa-br3dt-77erl-nlm7f-kplhq-php75-hw3an-aeqn2-swh4t-3qe",
                )
                .unwrap(),
            ),
            None,
        )
    );
}
