use std::str::FromStr;
use std::time::Duration;

use ic_base_types::CanisterId;
use ic_certification_test_utils::serialize_to_cbor;
use ic_certification_test_utils::CertificateData::CustomTree;
use ic_certification_test_utils::{CertificateBuilder, CertificateData::CanisterData};
use ic_certified_map::{labeled_hash, AsHashTree, Hash, HashTree, RbTree};
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_tree_hash::{flatmap, Digest, Label, LabeledTree};
use serde::{Deserialize, Serialize};

type AssetTree = RbTree<&'static str, Hash>;
const LABEL_ASSETS: &[u8] = b"http_assets";

#[derive(Serialize, Deserialize)]
struct QueryCallTestFixture {
    pub root_key: String,
    pub certificate: String,
    pub body: String,
    pub certificate_time: u128,
}

#[derive(Serialize, Deserialize)]
struct UpdateCallTestFixture {
    pub root_key: String,
    pub certificate: String,
    pub request_time: u64,
}

fn create_certificate_header<'a>(tree: &String, certificate: &String) -> String {
    format!("certificate=:{}:, tree=:{}:", certificate, tree)
}

fn create_asset_tree(path: &'static str, body: &str) -> AssetTree {
    let mut asset_tree: AssetTree = AssetTree::new();
    let content_hash = sha256::digest(body);

    asset_tree.insert(path, hex::decode(content_hash).unwrap().try_into().unwrap());

    asset_tree
}

fn serialize_hash_tree(path: &'static str, label: &[u8], tree: &AssetTree) -> String {
    let tree = tree.witness(path.as_bytes());
    let tree = ic_certified_map::labeled(label, tree);

    base64::encode(serialize_to_cbor::<HashTree>(&tree))
}

fn create_certificate(
    asset_tree: &AssetTree,
    canister_id: &CanisterId,
    certificate_time: u64,
) -> (String, String) {
    let certified_data = Digest(labeled_hash(LABEL_ASSETS, &asset_tree.root_hash()));
    let (_cert, root_key, cbor) = CertificateBuilder::new(CanisterData {
        canister_id: *canister_id,
        certified_data,
    })
    .with_time(certificate_time)
    .build();

    let certificate = base64::encode(&cbor);
    let root_key = hex::encode(threshold_sig_public_key_to_der(root_key).unwrap());

    (certificate, root_key)
}

fn create_canister_id(canister_id: &str) -> CanisterId {
    CanisterId::from_str(canister_id).unwrap()
}

fn create_query_call_fixture() -> QueryCallTestFixture {
    let path = "/";
    let body = "hello world!";
    let canister_id = "qoctq-giaaa-aaaaa-aaaea-cai";
    let certificate_time = 1651142233000005031;

    let asset_tree = create_asset_tree(path, body);
    let canister_id = create_canister_id(canister_id);

    let (certificate, root_key) = create_certificate(&asset_tree, &canister_id, certificate_time);
    let tree = serialize_hash_tree(path, LABEL_ASSETS, &asset_tree);

    QueryCallTestFixture {
        root_key,
        certificate: create_certificate_header(&tree, &certificate),
        body: body.to_string(),
        certificate_time: Duration::from_nanos(certificate_time).as_millis(),
    }
}

fn create_query_call_fixture_with_index_html_fallback() -> QueryCallTestFixture {
    let path = "/index.html";
    let body = "hello world!";
    let canister_id = "qoctq-giaaa-aaaaa-aaaea-cai";
    let certificate_time = 1651142233000005031;

    let asset_tree = create_asset_tree(path, body);
    let canister_id = create_canister_id(canister_id);

    let (certificate, root_key) = create_certificate(&asset_tree, &canister_id, certificate_time);
    let tree = serialize_hash_tree(path, LABEL_ASSETS, &asset_tree);

    QueryCallTestFixture {
        root_key,
        certificate: create_certificate_header(&tree, &certificate),
        body: body.to_string(),
        certificate_time: Duration::from_nanos(certificate_time).as_millis(),
    }
}

fn create_query_call_fixture_with_dscvr_canister_id() -> QueryCallTestFixture {
    let path = "/";
    let body = "hello world!";
    let canister_id = "h5aet-waaaa-aaaab-qaamq-cai";
    let certificate_time = 1651142233000005031;

    let asset_tree = create_asset_tree(path, body);
    let canister_id = create_canister_id(canister_id);

    let (certificate, root_key) = create_certificate(&asset_tree, &canister_id, certificate_time);
    let tree = serialize_hash_tree(path, LABEL_ASSETS, &asset_tree);

    QueryCallTestFixture {
        root_key,
        certificate: create_certificate_header(&tree, &certificate),
        body: body.to_string(),
        certificate_time: Duration::from_nanos(certificate_time).as_millis(),
    }
}

fn create_query_call_fixture_with_no_witness() -> QueryCallTestFixture {
    let path = "/";
    let body = "hello world!";
    let canister_id = "qoctq-giaaa-aaaaa-aaaea-cai";
    let certificate_time = 1651142233000005031;

    let asset_tree = create_asset_tree(path, body);
    let canister_id = create_canister_id(canister_id);

    let (certificate, root_key) = create_certificate(&asset_tree, &canister_id, certificate_time);
    let tree = serialize_hash_tree(path, b"not_http_assets", &asset_tree);

    QueryCallTestFixture {
        root_key,
        certificate: create_certificate_header(&tree, &certificate),
        body: body.to_string(),
        certificate_time: Duration::from_nanos(certificate_time).as_millis(),
    }
}

fn create_query_call_fixture_with_invalid_witness() -> QueryCallTestFixture {
    let path = "/";
    let body = "hello world!";
    let body2 = "hello world again!";
    let canister_id = "qoctq-giaaa-aaaaa-aaaea-cai";
    let certificate_time = 1651142233000005031;

    let asset_tree = create_asset_tree(path, body);
    let asset_tree2 = create_asset_tree(path, body2);
    let canister_id = create_canister_id(canister_id);

    let (certificate, root_key) = create_certificate(&asset_tree, &canister_id, certificate_time);
    let tree = serialize_hash_tree(path, LABEL_ASSETS, &asset_tree2);

    QueryCallTestFixture {
        root_key,
        certificate: create_certificate_header(&tree, &certificate),
        body: body.to_string(),
        certificate_time: Duration::from_nanos(certificate_time).as_millis(),
    }
}

fn create_update_call_fixture() -> UpdateCallTestFixture {
    let tree = LabeledTree::SubTree(flatmap![
        Label::from("request_status") => LabeledTree::SubTree(flatmap![
            Label::from(hex::decode("431f260d11977d02dcf08077782e0085846b3808b3147a4e12fa9d6905cdd9d8").unwrap()) => LabeledTree::SubTree(flatmap![
                Label::from("reply") => LabeledTree::Leaf(hex::decode("4449444c046d7b6c02007101716d016c03a2f5ed880400c6a4a19806029aa1b2f90c7a01030c68656c6c6f20776f726c642100c800").unwrap()),
                Label::from("status") => LabeledTree::Leaf(b"replied".to_vec())
            ])
        ])
    ]);
    let certificate_data = CustomTree(tree.clone());
    let (_cert, root_key, cbor) = CertificateBuilder::new(certificate_data).build();
    let certificate = hex::encode(&cbor);
    let root_key = hex::encode(threshold_sig_public_key_to_der(root_key).unwrap());

    UpdateCallTestFixture {
        root_key,
        certificate,
        request_time: 1650551764352,
    }
}

#[derive(Serialize, Deserialize)]
struct AllTestFixtures {
    pub query_call: QueryCallTestFixture,
    pub query_call_with_index_html_fallback: QueryCallTestFixture,
    pub query_call_with_dscvr_canister_id: QueryCallTestFixture,
    pub query_call_with_no_witness: QueryCallTestFixture,
    pub query_call_with_invalid_witness: QueryCallTestFixture,
    pub update_call: UpdateCallTestFixture,
}

fn main() {
    let fixtures = AllTestFixtures {
        query_call: create_query_call_fixture(),
        query_call_with_index_html_fallback: create_query_call_fixture_with_index_html_fallback(),
        query_call_with_dscvr_canister_id: create_query_call_fixture_with_dscvr_canister_id(),
        query_call_with_no_witness: create_query_call_fixture_with_no_witness(),
        query_call_with_invalid_witness: create_query_call_fixture_with_invalid_witness(),
        update_call: create_update_call_fixture(),
    };

    let json_fixtures = serde_json::to_string_pretty(&fixtures).unwrap();

    println!("{}", json_fixtures);

    std::fs::write("fixtures.json", json_fixtures).unwrap();
}
