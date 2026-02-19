pub mod types;
use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId, VetKDPublicKeyArgs};
use ic_cdk::{init, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    Cell as StableCell, DefaultMemoryImpl, StableBTreeMap,
};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use types::Signature;

type Memory = VirtualMemory<DefaultMemoryImpl>;

type VetKeyPublicKey = ByteBuf;
type RawSignature = ByteBuf;
type RawMessage = String;
type Timestamp = u64;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SIGNATURES: RefCell<StableBTreeMap<(Principal, Timestamp), Signature, Memory>> = RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(3))),
        ));

    static KEY_NAME: RefCell<StableCell<String, Memory>> =
        RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
            String::new(),
        )
        .expect("failed to initialize key name"));
}

#[init]
fn init(key_name_string: String) {
    KEY_NAME.with_borrow_mut(|key_name| {
        key_name
            .set(key_name_string)
            .expect("failed to set key name");
    });
}

#[update]
async fn sign_message(message: RawMessage) -> RawSignature {
    let signer = ic_cdk::api::msg_caller();
    let signature_bytes = ic_vetkeys::management_canister::sign_with_bls(
        message.as_bytes().to_vec(),
        context(&signer),
        key_id(),
    )
    .await
    .expect("ic_vetkeys' sign_with_bls failed");

    SIGNATURES.with_borrow_mut(|sigs| {
        let timestamp = ic_cdk::api::time();
        let sig = Signature {
            message,
            signature: signature_bytes.clone(),
            timestamp,
        };

        // In rare cases a user may call `sign_message` in quick succession
        // so that multiple signature requests are in a single consensus round,
        // which leads to ic_cdk::api::time() returning the same value for all
        // of the requests. In that case, we just keep increasing the timestamp
        // used in the map key until we hit a slot this is available.
        let mut timestamp_for_mapkey = timestamp;
        while sigs.get(&(signer, timestamp_for_mapkey)).is_some() {
            timestamp_for_mapkey += 1;
        }

        assert!(sigs.insert((signer, timestamp_for_mapkey), sig).is_none());
    });

    ByteBuf::from(signature_bytes)
}

#[query]
fn get_my_signatures() -> Vec<Signature> {
    let me = ic_cdk::api::msg_caller();
    SIGNATURES.with_borrow(|signer_and_timestamp_to_sig| {
        signer_and_timestamp_to_sig
            .range((me, 0)..)
            .take_while(|((signer, _ts), _sig)| signer == &me)
            .map(|((_, _), sig)| sig)
            .collect()
    })
}

#[update]
async fn get_my_verification_key() -> VetKeyPublicKey {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: context(&ic_cdk::api::msg_caller()),
        key_id: key_id(),
    };
    let result = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("call to vetkd_public_key failed");

    VetKeyPublicKey::from(result.public_key)
}

fn context(signer: &Principal) -> Vec<u8> {
    // A domain separator is not strictly necessary in this dapp, but having one is considered a good practice.
    const DOMAIN_SEPARATOR: [u8; 22] = *b"basic_bls_signing_dapp";
    const DOMAIN_SEPARATOR_LENGTH: u8 = DOMAIN_SEPARATOR.len() as u8;
    [DOMAIN_SEPARATOR_LENGTH]
        .into_iter()
        .chain(DOMAIN_SEPARATOR)
        .chain(signer.as_ref().iter().cloned())
        .collect()
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.with_borrow(|key_name| key_name.get().clone()),
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();
