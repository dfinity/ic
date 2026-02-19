use std::cell::RefCell;

use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_cdk::{init, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::DefaultMemoryImpl;
use ic_vetkeys::key_manager::{KeyManager, VetKey, VetKeyVerificationKey};
use ic_vetkeys::types::{AccessRights, ByteBuf, TransportKey};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static KEY_MANAGER: RefCell<Option<KeyManager<AccessRights>>> =
        const { RefCell::new(None) };
}

#[init]
fn init(key_name: String) {
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: key_name,
    };
    KEY_MANAGER.with_borrow_mut(|km| {
        km.replace(KeyManager::init(
            "key_manager_dapp",
            key_id,
            id_to_memory(0),
            id_to_memory(1),
            id_to_memory(2),
        ))
    });
}

#[query]
fn get_accessible_shared_key_ids() -> Vec<(Principal, ByteBuf)> {
    KEY_MANAGER.with_borrow(|km| {
        km.as_ref()
            .unwrap()
            .get_accessible_shared_key_ids(ic_cdk::api::msg_caller())
            .into_iter()
            .map(|key_id| (key_id.0, ByteBuf::from(key_id.1.as_ref().to_vec())))
            .collect()
    })
}

#[query]
fn get_shared_user_access_for_key(
    key_owner: Principal,
    key_name: ByteBuf,
) -> Result<Vec<(Principal, AccessRights)>, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    KEY_MANAGER.with_borrow(|km| {
        km.as_ref()
            .unwrap()
            .get_shared_user_access_for_key(ic_cdk::api::msg_caller(), key_id)
    })
}

#[update]
async fn get_vetkey_verification_key() -> VetKeyVerificationKey {
    KEY_MANAGER
        .with_borrow(|km| km.as_ref().unwrap().get_vetkey_verification_key())
        .await
}

#[update]
async fn get_encrypted_vetkey(
    key_owner: Principal,
    key_name: ByteBuf,
    transport_key: TransportKey,
) -> Result<VetKey, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    Ok(KEY_MANAGER
        .with_borrow(|km| {
            km.as_ref().unwrap().get_encrypted_vetkey(
                ic_cdk::api::msg_caller(),
                key_id,
                transport_key,
            )
        })?
        .await)
}

#[query]
fn get_user_rights(
    key_owner: Principal,
    key_name: ByteBuf,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    KEY_MANAGER.with_borrow(|km| {
        km.as_ref()
            .unwrap()
            .get_user_rights(ic_cdk::api::msg_caller(), key_id, user)
    })
}

#[update]
fn set_user_rights(
    key_owner: Principal,
    key_name: ByteBuf,
    user: Principal,
    access_rights: AccessRights,
) -> Result<Option<AccessRights>, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    KEY_MANAGER.with_borrow_mut(|km| {
        km.as_mut()
            .unwrap()
            .set_user_rights(ic_cdk::api::msg_caller(), key_id, user, access_rights)
    })
}

#[update]
fn remove_user(
    key_owner: Principal,
    key_name: ByteBuf,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    KEY_MANAGER.with_borrow_mut(|km| {
        km.as_mut()
            .unwrap()
            .remove_user(ic_cdk::api::msg_caller(), key_id, user)
    })
}

fn bytebuf_to_blob(buf: ByteBuf) -> Result<Blob<32>, String> {
    Blob::try_from(buf.as_ref()).map_err(|_| "too large input".to_string())
}

fn id_to_memory(id: u8) -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(id)))
}

ic_cdk::export_candid!();
