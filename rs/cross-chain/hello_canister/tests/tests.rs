use candid::{Decode, Encode, Principal};
use pocket_ic::PocketIc;

#[test]
fn test_greet() {
    let setup = Setup::default();
    let hello_canister = setup.hello_canister();

    let greeting = hello_canister.greet("World");

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
            hello_canister_wasm(),
            Encode!(&()).unwrap(),
            Some(Self::CONTROLLER),
        );
        Self { env, canister_id }
    }

    pub fn hello_canister(&self) -> HelloCanister<'_> {
        HelloCanister {
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

fn hello_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var("HELLO_CANISTER_WASM_PATH").expect("missing wasm path env var");
    std::fs::read(wasm_path).expect("failed to read canister wasm")
}

pub struct HelloCanister<'a> {
    env: &'a PocketIc,
    canister_id: Principal,
}

impl<'a> HelloCanister<'a> {
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
