use crate::common::system_test_environment::RosettaTestingEnvironment;
use ic_rosetta_api::API_VERSION;
use ic_rosetta_api::NODE_VERSION;
use tokio::runtime::Runtime;

#[test]
fn test_network_list() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let network_list = rosetta_testing_environment
            .rosetta_client
            .network_list()
            .await
            .unwrap();
        assert_eq!(network_list.network_identifiers.len(), 1);
        assert_eq!(
            network_list.network_identifiers[0].clone(),
            rosetta_testing_environment.network_identifier
        );
    });
}

#[test]
fn test_network_options() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let network_options = rosetta_testing_environment
            .rosetta_client
            .network_options(rosetta_testing_environment.network_identifier.clone())
            .await
            .unwrap();

        assert_eq!(network_options.version.rosetta_version, API_VERSION);
        assert_eq!(network_options.version.node_version, NODE_VERSION);
        assert!(!network_options.allow.operation_statuses.is_empty());
        assert!(
            network_options
                .allow
                .operation_types
                .contains(&"TRANSACTION".to_string())
        );
        assert!(
            network_options
                .allow
                .operation_types
                .contains(&"FEE".to_string())
        );
        assert!(!network_options.allow.errors.is_empty());
        assert!(network_options.allow.historical_balance_lookup);
    });
}
