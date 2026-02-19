use candid::{decode_one, encode_one, CandidType, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::path::Path;

#[allow(dead_code)]
pub const NANOSECONDS_IN_MINUTE: u64 = 60_000_000_000;

pub fn reproducible_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed);
    let rng = ChaCha20Rng::from_seed(seed);
    println!("{seed:?}");
    rng
}

pub fn random_self_authenticating_principal<R: Rng + CryptoRng>(rng: &mut R) -> Principal {
    let fake_pk = random_bytes(32, rng);
    Principal::self_authenticating(&fake_pk)
}

pub fn random_bytes<R: Rng + CryptoRng>(size: usize, rng: &mut R) -> Vec<u8> {
    let mut buf = vec![0; size];
    rng.fill_bytes(&mut buf);
    buf
}

pub struct TestEnvironment {
    pub pic: PocketIc,
    pub canister_id: Principal,
    #[allow(dead_code)]
    pub principal_0: Principal,
    #[allow(dead_code)]
    pub principal_1: Principal,
    #[allow(dead_code)]
    pub principal_2: Principal,
}

impl TestEnvironment {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let pic = PocketIcBuilder::new()
            .with_application_subnet()
            .with_ii_subnet()
            .with_fiduciary_subnet()
            .with_nonmainnet_features(true)
            .build();

        let canister_id = pic.create_canister();
        pic.add_cycles(canister_id, 2_000_000_000_000);

        let wasm_bytes = load_canister_wasm();
        pic.install_canister(
            canister_id,
            wasm_bytes,
            encode_one("dfx_test_key").unwrap(),
            None,
        );

        // Make sure the canister is properly initialized
        fast_forward(&pic, 5);

        Self {
            pic,
            canister_id,
            principal_0: random_self_authenticating_principal(rng),
            principal_1: random_self_authenticating_principal(rng),
            principal_2: random_self_authenticating_principal(rng),
        }
    }

    pub fn update<T: CandidType + for<'de> candid::Deserialize<'de>>(
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

    pub fn query<T: CandidType + for<'de> candid::Deserialize<'de>>(
        &self,
        caller: Principal,
        method_name: &str,
        args: Vec<u8>,
    ) -> T {
        let reply = self
            .pic
            .query_call(self.canister_id, caller, method_name, args);
        match reply {
            Ok(data) => decode_one(&data).expect("failed to decode reply"),
            Err(user_error) => panic!("canister returned a user error: {user_error}"),
        }
    }
}

fn fast_forward(ic: &PocketIc, ticks: u64) {
    for _ in 0..ticks - 1 {
        ic.tick();
    }
}

fn load_canister_wasm() -> Vec<u8> {
    let wasm_path_string = match std::env::var("CUSTOM_WASM_PATH") {
        Ok(path) if !path.is_empty() => path,
        _ => format!(
            "{}/examples/encrypted_chat/rust/target/wasm32-unknown-unknown/release/ic_vetkeys_example_encrypted_chat_backend.wasm",
            git_root_dir()
        ),
    };
    let wasm_path = Path::new(&wasm_path_string);
    std::fs::read(wasm_path)
        .expect("wasm does not exist - run `cargo build --release --target wasm32-unknown-unknown`")
}

pub fn git_root_dir() -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("Failed to execute git command");
    assert!(output.status.success());
    let root_dir_with_newline =
        String::from_utf8(output.stdout).expect("Failed to convert stdout to string");
    root_dir_with_newline.trim_end_matches('\n').to_string()
}
