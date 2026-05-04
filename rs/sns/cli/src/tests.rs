use super::*;

use lazy_static::lazy_static;

lazy_static! {
    static ref CARGO_MANIFEST_DIR: String = std::env::var("CARGO_MANIFEST_DIR").unwrap();
}

#[test]
fn test_generate_sns_init_payload() {
    let input_path = Path::new(&*CARGO_MANIFEST_DIR).join("test_sns_init_v2.yaml");

    let sns_init_payload = generate_sns_init_payload(&input_path)
        .expect("Unable to load SnsInitPayload using format v2.");

    assert_eq!(
        sns_init_payload.name,
        Some("Daniel".to_string()),
        "{sns_init_payload:#?}"
    );
}
