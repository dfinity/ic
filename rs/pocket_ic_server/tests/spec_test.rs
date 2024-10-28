mod common;

use crate::common::raw_canister_id_range_into;
use candid::Principal;
use ic_registry_routing_table::{canister_id_into_u64, CanisterIdRange};
use ic_registry_subnet_type::SubnetType;
use pocket_ic::common::rest::DtsFlag;
use pocket_ic::PocketIcBuilder;
use spec_compliance::run_ic_ref_test;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const EXCLUDED: &[&str] = &[
    // we do not enforce https in PocketIC
    "$0 ~ /url must start with https:/",
    // replica issues
    "$0 ~ /wrong effective canister id.in management call/",
    "$0 ~ /access denied with different effective canister id/",
    "$0 ~ /Call from query method traps (in query call)/",
];

fn subnet_config(
    subnet_id: Principal,
    subnet_type: SubnetType,
    node_ids: Vec<Principal>,
    canister_ranges: Vec<CanisterIdRange>,
) -> String {
    format!(
        "(\"{}\",{},[{}],[{}],[])",
        subnet_id,
        match subnet_type {
            SubnetType::VerifiedApplication => "verified_application",
            SubnetType::Application => "application",
            SubnetType::System => "system",
        },
        node_ids
            .into_iter()
            .map(|n| format!("\"{}\"", n))
            .collect::<Vec<String>>()
            .join(","),
        canister_ranges
            .iter()
            .map(|r| format!(
                "({},{})",
                canister_id_into_u64(r.start),
                canister_id_into_u64(r.end)
            ))
            .collect::<Vec<String>>()
            .join(","),
    )
}

fn setup_and_run_ic_ref_test(test_nns: bool, excluded_tests: Vec<&str>, included_tests: Vec<&str>) {
    // the following root TLS certificate has been generated using
    // ```
    // use rcgen::{CertificateParams, KeyPair};
    // let root_key_pair = KeyPair::generate().unwrap();
    // let root_cert = CertificateParams::new(vec!["localhost".to_string()])
    //     .unwrap()
    //     .self_signed(&root_key_pair)
    //     .unwrap();
    // println!("key: {}", hex::encode(root_key_pair.serialize_pem().as_bytes()));
    // println!("cert: {}", hex::encode(root_cert.pem().as_bytes()));
    // ```
    let key = hex::decode("2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d494748416745414d424d4742797147534d34394167454743437147534d343941774548424730776177494241515167354b43675163774d746a796c624938380a717a766e356464706651584b56437471756a5174517972744a752b6852414e434141537775576b6b6b646149316e6952336f44444e3234643870637278634a540a5564515a49786d434d6d494968307264562f33595475517538786e585a4b37344242366679455a7242354d31547a452b716a3871455a66450a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a").unwrap();
    let cert = hex::decode("2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494942586a4343415153674177494241674955477a7235384c654c52624531343565446b5a495744574e6f51357777436759494b6f5a497a6a3045417749770a495445664d4230474131554541777757636d4e6e5a573467633256735a69427a615764755a5751675932567964444167467730334e5441784d4445774d4441770a4d444261474138304d446b324d4445774d5441774d4441774d466f77495445664d4230474131554541777757636d4e6e5a573467633256735a69427a615764750a5a575167593256796444425a4d424d4742797147534d34394167454743437147534d34394177454841304941424c433561535352316f6a57654a4865674d4d330a626833796c797646776c4e5231426b6a4759497959676948537431582f64684f3543377a4764646b7276674548702f49526d73486b7a56504d54367150796f520a6c38536a474441574d425147413155644551514e4d41754343577876593246736147397a6444414b42676771686b6a4f5051514441674e4941444246416941730a5236316951304c4e4d30766a7a3235473330794d3830354d465749314f414c656a34694d7869576d43514968414e61464a6c53336158384274635a356e764f350a59564f34576c3263752f36656b52706576793032704474350a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a").unwrap();

    // store the private key and public certificate into files
    let (mut key_file, key_path) = NamedTempFile::new().unwrap().keep().unwrap();
    key_file.write_all(&key).unwrap();
    let (mut cert_file, cert_path) = NamedTempFile::new().unwrap().keep().unwrap();
    cert_file.write_all(&cert).unwrap();

    // set `SSL_CERT_FILE` so that the canister http outcalls adapter accepts the self-signed certificate
    // (this affects all tests and thus the certificate is hard-coded above)
    std::env::set_var("SSL_CERT_FILE", cert_path.clone());
    std::env::remove_var("NIX_SSL_CERT_FILE");

    // start httpbin webserver to test canister HTTP outcalls
    let httpbin_path = std::env::var_os("HTTPBIN_BIN").expect("Missing httpbin binary path");
    let mut cmd = Command::new(httpbin_path);
    let port_file = NamedTempFile::new().unwrap();
    let port_file_path = port_file.path().to_path_buf();
    cmd.arg("--port-file")
        .arg(port_file_path.as_os_str().to_str().unwrap());
    cmd.arg("--cert-file").arg(cert_path);
    cmd.arg("--key-file").arg(key_path);
    cmd.stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("httpbin binary crashed");
    let httpbin_url = loop {
        let port_string = std::fs::read_to_string(port_file_path.clone())
            .expect("Failed to read port from port file");
        if !port_string.is_empty() {
            let port: u16 = port_string
                .trim_end()
                .parse()
                .expect("Failed to parse port to number");
            break format!("localhost:{}", port);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // create live PocketIc instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_dts_flag(DtsFlag::Disabled)
        .build();
    let endpoint = pic.make_live(None);
    let topo = pic.topology();
    let app_subnet_id = topo.get_app_subnets()[0];
    let app_config = topo.subnet_configs.get(&app_subnet_id).unwrap();
    let app_node_ids = app_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();
    let nns_subnet_id = topo.get_nns().unwrap();
    let nns_config = topo.subnet_configs.get(&nns_subnet_id).unwrap();
    let nns_node_ids = nns_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();

    // derive artifact paths
    let ic_ref_test_root = std::env::var_os("IC_REF_TEST_ROOT")
        .expect("Missing ic-hs directory")
        .into_string()
        .unwrap();
    let root_dir = std::path::PathBuf::from(ic_ref_test_root);
    let mut ic_ref_test_path = root_dir.clone();
    ic_ref_test_path.push("bin");
    ic_ref_test_path.push("ic-ref-test");
    let mut ic_test_data_path = root_dir.clone();
    ic_test_data_path.push("test-data");

    // NNS subnet config
    let nns_canister_ranges = nns_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let nns_subnet_config = subnet_config(
        nns_subnet_id,
        SubnetType::System,
        nns_node_ids,
        nns_canister_ranges,
    );

    // app subnet config
    let app_canister_ranges = app_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let app_subnet_config = subnet_config(
        app_subnet_id,
        SubnetType::Application,
        app_node_ids,
        app_canister_ranges,
    );

    // decide on which subnet to test
    let test_subnet_config = if test_nns {
        nns_subnet_config.clone()
    } else {
        app_subnet_config.clone()
    };
    let peer_subnet_config = if test_nns {
        app_subnet_config
    } else {
        nns_subnet_config
    };

    run_ic_ref_test(
        Some("https://".to_string()),
        Some(httpbin_url),
        ic_ref_test_path.into_os_string().into_string().unwrap(),
        ic_test_data_path,
        endpoint.to_string(),
        test_subnet_config,
        peer_subnet_config,
        excluded_tests,
        included_tests,
        64,
    );
}

#[test]
fn ic_ref_test_nns() {
    setup_and_run_ic_ref_test(true, EXCLUDED.to_vec(), vec![])
}

#[test]
fn ic_ref_test_app() {
    setup_and_run_ic_ref_test(false, EXCLUDED.to_vec(), vec![])
}
