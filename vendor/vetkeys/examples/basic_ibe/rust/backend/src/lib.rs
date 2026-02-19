use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs};
use ic_cdk::{init, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap as StableBTreeMap, Cell as StableCell, DefaultMemoryImpl};
use serde_bytes::ByteBuf;
use std::cell::RefCell;

mod types;
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type EncryptedVetKey = ByteBuf;
type VetKeyPublicKey = ByteBuf;
type TransportPublicKey = ByteBuf;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static INBOXES: RefCell<StableBTreeMap<Principal, Inbox, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    ));
    static KEY_NAME: RefCell<StableCell<String, Memory>> =
        RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            String::new(),
        )
        .expect("failed to initialize key name"));
}

static DOMAIN_SEPARATOR: &str = "basic_ibe_example_dapp";

#[init]
fn init(key_name_string: String) {
    KEY_NAME.with_borrow_mut(|key_name| {
        key_name
            .set(key_name_string)
            .expect("failed to set key name");
    });
}

#[update]
fn send_message(request: SendMessageRequest) -> Result<(), String> {
    let sender = ic_cdk::api::msg_caller();
    let SendMessageRequest {
        receiver,
        encrypted_message,
    } = request;
    let timestamp = ic_cdk::api::time();

    let message = Message {
        sender,
        encrypted_message,
        timestamp,
    };

    INBOXES.with_borrow_mut(|inboxes| {
        let mut inbox = inboxes.get(&receiver).unwrap_or_default();

        if inbox.messages.len() >= MAX_MESSAGES_PER_INBOX {
            Err(format!("Inbox for {} is full", receiver))
        } else {
            inbox.messages.push(message);
            inboxes.insert(receiver, inbox);
            Ok(())
        }
    })
}

#[update]
async fn get_ibe_public_key() -> VetKeyPublicKey {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: DOMAIN_SEPARATOR.as_bytes().to_vec(),
        key_id: key_id(),
    };

    let result = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("call to vetkd_public_key failed");

    VetKeyPublicKey::from(result.public_key)
}

#[update]
/// Retrieves the caller's encrypted private IBE key for message decryption.
async fn get_my_encrypted_ibe_key(transport_key: TransportPublicKey) -> EncryptedVetKey {
    let caller = ic_cdk::api::msg_caller();
    let request = VetKDDeriveKeyArgs {
        input: caller.as_ref().to_vec(),
        context: DOMAIN_SEPARATOR.as_bytes().to_vec(),
        key_id: key_id(),
        transport_public_key: transport_key.into_vec(),
    };

    let result = ic_cdk::management_canister::vetkd_derive_key(&request)
        .await
        .expect("call to vetkd_derive_key failed");

    EncryptedVetKey::from(result.encrypted_key)
}

#[query]
fn get_my_messages() -> Inbox {
    let caller = ic_cdk::api::msg_caller();
    INBOXES.with_borrow(|inboxes| inboxes.get(&caller).unwrap_or_default())
}

#[update]
fn remove_my_message_by_index(message_index: usize) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INBOXES.with_borrow_mut(|inboxes| {
        let mut inbox = inboxes.get(&caller).unwrap_or_default();
        if message_index >= inbox.messages.len() {
            Err("Message index out of bounds".to_string())
        } else {
            inbox.messages.remove(message_index);
            inboxes.insert(caller, inbox);
            Ok(())
        }
    })
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.with_borrow(|key_name| key_name.get().clone()),
    }
}

ic_cdk::export_candid!();
