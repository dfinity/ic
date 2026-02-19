use std::cell::RefCell;

use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_cdk::{init, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::DefaultMemoryImpl;
use ic_vetkeys::encrypted_maps::{EncryptedMapData, EncryptedMaps, VetKey, VetKeyVerificationKey};
use ic_vetkeys::types::{AccessRights, ByteBuf, EncryptedMapValue, TransportKey};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type MapId = (Principal, ByteBuf);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static ENCRYPTED_MAPS: RefCell<Option<EncryptedMaps<AccessRights>>> =
        const { RefCell::new(None) };
}

#[init]
fn init(key_name: String) {
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: key_name,
    };
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps.replace(EncryptedMaps::init(
            "encrypted_maps_dapp",
            key_id,
            id_to_memory(0),
            id_to_memory(1),
            id_to_memory(2),
            id_to_memory(3),
        ))
    });
}

#[query]
fn get_accessible_shared_map_names() -> Vec<(Principal, ByteBuf)> {
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_accessible_shared_map_names(ic_cdk::api::msg_caller())
            .into_iter()
            .map(|map_id| (map_id.0, ByteBuf::from(map_id.1.as_ref().to_vec())))
            .collect()
    })
}

#[query]
fn get_shared_user_access_for_map(
    key_owner: Principal,
    key_name: ByteBuf,
) -> Result<Vec<(Principal, AccessRights)>, String> {
    let key_name = bytebuf_to_blob(key_name)?;
    let key_id = (key_owner, key_name);
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_shared_user_access_for_map(ic_cdk::api::msg_caller(), key_id)
    })
}

#[query]
fn get_encrypted_values_for_map(
    map_owner: Principal,
    map_name: ByteBuf,
) -> Result<Vec<(ByteBuf, EncryptedMapValue)>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    let result = ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_encrypted_values_for_map(ic_cdk::api::msg_caller(), map_id)
    });
    result.map(|map_values| {
        map_values
            .into_iter()
            .map(|(key, value)| (ByteBuf::from(key.as_slice().to_vec()), value))
            .collect()
    })
}

#[query]
fn get_all_accessible_encrypted_values() -> Vec<(MapId, Vec<(ByteBuf, EncryptedMapValue)>)> {
    ENCRYPTED_MAPS
        .with_borrow(|encrypted_maps| {
            encrypted_maps
                .as_ref()
                .unwrap()
                .get_all_accessible_encrypted_values(ic_cdk::api::msg_caller())
        })
        .into_iter()
        .map(|((owner, map_name), encrypted_values)| {
            (
                (owner, ByteBuf::from(map_name.as_ref().to_vec())),
                encrypted_values
                    .into_iter()
                    .map(|(key, value)| (ByteBuf::from(key.as_ref().to_vec()), value))
                    .collect(),
            )
        })
        .collect()
}

#[query]
fn get_all_accessible_encrypted_maps() -> Vec<EncryptedMapData<AccessRights>> {
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_all_accessible_encrypted_maps(ic_cdk::api::msg_caller())
    })
}

#[query]
fn get_encrypted_value(
    map_owner: Principal,
    map_name: ByteBuf,
    map_key: ByteBuf,
) -> Result<Option<EncryptedMapValue>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps.as_ref().unwrap().get_encrypted_value(
            ic_cdk::api::msg_caller(),
            map_id,
            bytebuf_to_blob(map_key)?,
        )
    })
}

#[update]
fn remove_map_values(
    map_owner: Principal,
    map_name: ByteBuf,
) -> Result<Vec<EncryptedMapValue>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    let result = ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps
            .as_mut()
            .unwrap()
            .remove_map_values(ic_cdk::api::msg_caller(), map_id)
    });
    result.map(|removed| {
        removed
            .into_iter()
            .map(|key| ByteBuf::from(key.as_ref().to_vec()))
            .collect()
    })
}

#[query]
fn get_owned_non_empty_map_names() -> Vec<ByteBuf> {
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_owned_non_empty_map_names(ic_cdk::api::msg_caller())
            .into_iter()
            .map(|map_name| ByteBuf::from(map_name.as_slice().to_vec()))
            .collect()
    })
}

#[update]
fn insert_encrypted_value(
    map_owner: Principal,
    map_name: ByteBuf,
    map_key: ByteBuf,
    value: EncryptedMapValue,
) -> Result<Option<EncryptedMapValue>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps.as_mut().unwrap().insert_encrypted_value(
            ic_cdk::api::msg_caller(),
            map_id,
            bytebuf_to_blob(map_key)?,
            value,
        )
    })
}

#[update]
fn remove_encrypted_value(
    map_owner: Principal,
    map_name: ByteBuf,
    map_key: ByteBuf,
) -> Result<Option<EncryptedMapValue>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps.as_mut().unwrap().remove_encrypted_value(
            ic_cdk::api::msg_caller(),
            map_id,
            bytebuf_to_blob(map_key)?,
        )
    })
}

#[update]
async fn get_vetkey_verification_key() -> VetKeyVerificationKey {
    ENCRYPTED_MAPS
        .with_borrow(|encrypted_maps| {
            encrypted_maps
                .as_ref()
                .unwrap()
                .get_vetkey_verification_key()
        })
        .await
}

#[update]
async fn get_encrypted_vetkey(
    map_owner: Principal,
    map_name: ByteBuf,
    transport_key: TransportKey,
) -> Result<VetKey, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    Ok(ENCRYPTED_MAPS
        .with_borrow(|encrypted_maps| {
            encrypted_maps.as_ref().unwrap().get_encrypted_vetkey(
                ic_cdk::api::msg_caller(),
                map_id,
                transport_key,
            )
        })?
        .await)
}

#[query]
fn get_user_rights(
    map_owner: Principal,
    map_name: ByteBuf,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_user_rights(ic_cdk::api::msg_caller(), map_id, user)
    })
}

#[update]
fn set_user_rights(
    map_owner: Principal,
    map_name: ByteBuf,
    user: Principal,
    access_rights: AccessRights,
) -> Result<Option<AccessRights>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps.as_mut().unwrap().set_user_rights(
            ic_cdk::api::msg_caller(),
            map_id,
            user,
            access_rights,
        )
    })
}

#[update]
fn remove_user(
    map_owner: Principal,
    map_name: ByteBuf,
    user: Principal,
) -> Result<Option<AccessRights>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps
            .as_mut()
            .unwrap()
            .remove_user(ic_cdk::api::msg_caller(), map_id, user)
    })
}

fn bytebuf_to_blob(buf: ByteBuf) -> Result<Blob<32>, String> {
    Blob::try_from(buf.as_ref()).map_err(|_| "too large input".to_string())
}

fn id_to_memory(id: u8) -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(id)))
}

ic_cdk::export_candid!();
