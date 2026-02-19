use candid::{decode_one, encode_args, CandidType, Principal};
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_vetkeys::{verify_bls_signature, DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use ic_vetkeys_test_utils::{git_root_dir, reproducible_rng};
use pocket_ic::{PocketIc, PocketIcBuilder};
use rand::{CryptoRng, Rng};
use std::path::Path;

#[test]
fn bls_signature_should_be_valid_and_equal_to_decrypted_vetkey() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new();
    let input = random_bytes(rng, 10);
    let context = random_bytes(rng, 10);
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    };
    let transport_secret_key = random_transport_key(rng);
    let transport_public_key = transport_secret_key.public_key();

    let bls_signature: Vec<u8> = env.update(
        Principal::anonymous(),
        "sign_with_bls",
        encode_args((input.clone(), context.clone(), key_id.clone())).unwrap(),
    );

    let verification_key: Vec<u8> = env.update(
        Principal::anonymous(),
        "vetkd_public_key",
        encode_args((context.clone(), key_id.clone())).unwrap(),
    );
    let encrypted_vetkey_bytes: Vec<u8> = env.update(
        Principal::anonymous(),
        "vetkd_derive_key",
        encode_args((input.clone(), context, key_id, transport_public_key)).unwrap(),
    );
    let encrypted_vetkey = EncryptedVetKey::deserialize(encrypted_vetkey_bytes.as_ref()).unwrap();
    let derived_public_key = DerivedPublicKey::deserialize(verification_key.as_ref()).unwrap();
    let decrypted_vetkey = encrypted_vetkey
        .decrypt_and_verify(&transport_secret_key, &derived_public_key, &input)
        .unwrap();

    assert_eq!(bls_signature, decrypted_vetkey.signature_bytes().to_vec());
    assert!(verify_bls_signature(
        &derived_public_key,
        &input,
        &bls_signature
    ));
}

#[test]
fn bls_public_key_should_be_equal_to_verification_key() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new();
    let context = random_bytes(rng, 10);
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    };
    let bls_public_key: Vec<u8> = env.update(
        Principal::anonymous(),
        "bls_public_key",
        encode_args((context.clone(), key_id.clone())).unwrap(),
    );
    let verification_key: Vec<u8> = env.update(
        Principal::anonymous(),
        "vetkd_public_key",
        encode_args((context.clone(), key_id.clone())).unwrap(),
    );
    assert_eq!(bls_public_key, verification_key);
}
struct TestEnvironment {
    pic: PocketIc,
    canister_id: Principal,
}

impl TestEnvironment {
    fn new() -> Self {
        let pic = PocketIcBuilder::new()
            .with_application_subnet()
            .with_ii_subnet()
            .with_fiduciary_subnet()
            .with_nonmainnet_features(true)
            .build();

        let canister_id = pic.create_canister();
        pic.add_cycles(canister_id, 2_000_000_000_000);

        let wasm_bytes = load_canister_wasm();
        pic.install_canister(canister_id, wasm_bytes, vec![], None);

        // Make sure the canister is properly initialized
        fast_forward(&pic, 5);

        Self { pic, canister_id }
    }

    fn update<T: CandidType + for<'de> candid::Deserialize<'de>>(
        &self,
        caller: Principal,
        method_name: &str,
        args: Vec<u8>,
    ) -> T {
        let reply = self
            .pic
            .update_call(self.canister_id, caller, method_name, args);
        match reply {
            Ok(data) => decode_one(&data).expect("failed to decode reply"),
            Err(user_error) => panic!("canister returned a user error: {user_error}"),
        }
    }
}

fn load_canister_wasm() -> Vec<u8> {
    let wasm_path_string = match std::env::var("CUSTOM_WASM_PATH") {
        Ok(path) if !path.is_empty() => path,
        _ => format!(
            "{}/target/wasm32-unknown-unknown/release/ic_vetkeys_canisters_tests.wasm",
            git_root_dir()
        ),
    };
    let wasm_path = Path::new(&wasm_path_string);
    std::fs::read(wasm_path)
        .expect("wasm does not exist - run `cargo build --release --target wasm32-unknown-unknown`")
}

fn random_transport_key<R: Rng + CryptoRng>(rng: &mut R) -> TransportSecretKey {
    let mut seed = vec![0u8; 32];
    rng.fill_bytes(&mut seed);
    TransportSecretKey::from_seed(seed).unwrap()
}

fn random_bytes<R: Rng + CryptoRng>(rng: &mut R, max_length: usize) -> Vec<u8> {
    let length = rng.gen_range(0..max_length);
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn fast_forward(ic: &PocketIc, ticks: u64) {
    for _ in 0..ticks - 1 {
        ic.tick();
    }
}
