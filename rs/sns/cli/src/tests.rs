use super::*;

use lazy_static::lazy_static;

lazy_static! {
    static ref CARGO_MANIFEST_DIR: String = std::env::var("CARGO_MANIFEST_DIR").unwrap();
}

#[test]
fn test_generate_sns_init_payload_v1() {
    let input_path = Path::new(&*CARGO_MANIFEST_DIR).join("example_sns_init_v1.yaml");

    let sns_init_payload = generate_sns_init_payload(&input_path)
        .expect("Unable to load SnsInitPayload using format v1");

    assert_eq!(
        sns_init_payload.name,
        Some("My Testnet Token".to_string()),
        "{:#?}",
        sns_init_payload
    );
}

#[test]
fn test_generate_sns_init_payload_v2() {
    let input_path = Path::new(&*CARGO_MANIFEST_DIR).join("example_sns_init_v2.yaml");

    let sns_init_payload = generate_sns_init_payload(&input_path)
        .expect("Unable to load SnsInitPayload using format v2.");

    assert_eq!(
        sns_init_payload.name,
        Some("Daniel".to_string()),
        "{:#?}",
        sns_init_payload
    );
}
