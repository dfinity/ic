use candid::{Decode, Encode, Principal};
use pocket_ic::PocketIc;

#[test]
fn test_greet() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let greeting = blob_store.greet("World");

    assert_eq!(greeting, "Hello, World!");
}

pub struct Setup {
    pub env: PocketIc,
    pub canister_id: Principal,
}

impl Setup {
    pub const CONTROLLER: Principal = Principal::from_slice(&[0_u8, 1, 2]);

    pub fn new() -> Self {
        let env = PocketIc::new();
        let canister_id = env.create_canister_with_settings(Some(Self::CONTROLLER), None);
        env.add_cycles(canister_id, 3_000_000_000_000);
        env.install_canister(
            canister_id,
            blob_store_wasm(),
            Encode!(&()).unwrap(),
            Some(Self::CONTROLLER),
        );
        Self { env, canister_id }
    }

    pub fn blob_store(&self) -> BlobStoreCanister<'_> {
        BlobStoreCanister {
            env: &self.env,
            canister_id: self.canister_id,
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

fn blob_store_wasm() -> Vec<u8> {
    let wasm_path =
        std::env::var("BLOB_STORE_CANISTER_WASM_PATH").expect("missing wasm path env var");
    std::fs::read(wasm_path).expect("failed to read canister wasm")
}

pub struct BlobStoreCanister<'a> {
    env: &'a PocketIc,
    canister_id: Principal,
}

impl<'a> BlobStoreCanister<'a> {
    pub fn greet(&self, name: &str) -> String {
        let result = self
            .env
            .query_call(
                self.canister_id,
                Principal::anonymous(),
                "greet",
                Encode!(&name).unwrap(),
            )
            .expect("query call failed");
        Decode!(&result, String).unwrap()
    }
}
