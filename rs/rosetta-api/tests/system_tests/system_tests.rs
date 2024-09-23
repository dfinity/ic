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
