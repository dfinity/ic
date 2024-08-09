use candid::Principal;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_nns_canisters;
use pocket_ic::{PocketIc, PocketIcBuilder};
use std::{env, io::Write, process::Command};
use tempfile::NamedTempFile;
use url::Url;

fn setup() -> (PocketIc, Url) {
    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let _ = install_nns_canisters(&pocket_ic, vec![], false, None, vec![]);
    let endpoint = pocket_ic.make_live(None);
    (pocket_ic, endpoint)
}

fn create_neuron_1_pem_file() -> NamedTempFile {
    let contents: String = TEST_NEURON_1_OWNER_KEYPAIR.to_pem();
    let mut pem_file = NamedTempFile::new().expect("Unable to create a temporary file");
    pem_file
        .write_all(contents.as_bytes())
        .expect("Unable to write to file");
    pem_file
}

#[test]
fn test_propose_to_rent_subnet_can_read_pem_file() {
    let (_pocket_ic, url) = setup();

    let ic_admin_path = env::var("IC_ADMIN_BIN").expect("IC_ADMIN_BIN not set");
    let pem_file = create_neuron_1_pem_file();
    let pem_file_path = pem_file
        .path()
        .to_str()
        .expect("Failed to get pem file path");
    let neuron_id = TEST_NEURON_1_ID.to_string();

    let output = Command::new(ic_admin_path)
        .args([
            "--nns-url",
            url.as_ref(),
            "--secret-key-pem",
            pem_file_path,
            "propose-to-rent-subnet",
            "--proposer",
            &neuron_id,
            "--summary",
            "This is the summary.",
            "--rental-condition-id",
            "App13CH",
            "--user",
            &Principal::anonymous().to_string(), // Not related to the pem file, will be whitelisted on the subnet
        ])
        .output()
        .expect("Failed to run ic-admin");

    let stderr: String = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code().unwrap(),
        0,
        "ic-admin's status code was not 0"
    );
    assert!(stderr.contains("response: Ok(proposal 1)"));
}
