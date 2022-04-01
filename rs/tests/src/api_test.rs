//! This module tests the system tests API itself.

use crate::driver::{
    ic::InternetComputer,
    test_env::TestEnv,
    test_env_api::{DefaultIC, HasHttpFileStore},
};
use ic_registry_subnet_type::SubnetType;
use slog::Logger;
use std::fs::File;

/// Create two ICs, a no-name IC and a named one which differ in their topology.
pub fn two_ics(test_env: TestEnv) {
    let mut ic = InternetComputer::new().add_fast_single_node_subnet(SubnetType::System);
    ic.setup_and_start(&test_env)
        .expect("Could not start no-name IC");

    let mut ic2 = InternetComputer::new()
        .with_name("two_subnets")
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application);
    ic2.setup_and_start(&test_env)
        .expect("Could not start second IC");
}

pub fn ics_have_correct_subnet_count(test_env: TestEnv, _logger: Logger) {
    let topo_snapshot = test_env.topology_snapshot();
    assert_eq!(topo_snapshot.subnets().count(), 1);

    let topo_snapshot2 = test_env.topology_snapshot_by_name("two_subnets");
    assert_eq!(topo_snapshot2.subnets().count(), 2);
}

pub fn upload_file_to_farm(test_env: TestEnv, _: Logger) {
    test_env
        .write_object("uploaded", &String::from("magic"))
        .expect("failed to write to env");
    let fm = test_env.http_file_store();
    let fh = fm
        .upload(test_env.get_path("uploaded"))
        .expect("failed to upload file to farm");
    let sink = File::create(test_env.get_path("downloaded")).expect("cannot create output file");
    fh.download(Box::new(sink))
        .expect("failed to download file from farm");

    let uploaded: String = test_env.read_object("uploaded").unwrap();
    let downloaded: String = test_env.read_object("downloaded").unwrap();
    assert_eq!(uploaded, downloaded);
}
