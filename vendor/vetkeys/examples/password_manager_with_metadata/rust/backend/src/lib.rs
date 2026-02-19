use candid::{CandidType, Principal};
use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
use ic_cdk::{init, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{storable::Bound, Storable};
use ic_stable_structures::{BTreeMap as StableBTreeMap, DefaultMemoryImpl};
use ic_vetkeys::encrypted_maps::{EncryptedMaps, VetKey, VetKeyVerificationKey};
use ic_vetkeys::types::{AccessRights, ByteBuf, EncryptedMapValue, TransportKey};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct PasswordMetadata {
    creation_date: u64,
    last_modification_date: u64,
    number_of_modifications: u64,
    last_modified_principal: Principal,
    tags: Vec<String>,
    url: String,
}

impl PasswordMetadata {
    pub fn new(caller: Principal, tags: Vec<String>, url: String) -> Self {
        let time_now = ic_cdk::api::time();
        Self {
            creation_date: time_now,
            last_modification_date: time_now,
            number_of_modifications: 0,
            last_modified_principal: caller,
            tags,
            url,
        }
    }

    pub fn update(self, caller: Principal, tags: Vec<String>, url: String) -> Self {
        let time_now = ic_cdk::api::time();
        Self {
            creation_date: self.creation_date,
            last_modification_date: time_now,
            number_of_modifications: self.number_of_modifications + 1,
            last_modified_principal: caller,
            tags,
            url,
        }
    }
}

impl Storable for PasswordMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(bytes.as_ref()).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

type Memory = VirtualMemory<DefaultMemoryImpl>;
type MapOwner = Principal;
type MapName = Blob<32>;
type MapKey = Blob<32>;
// To understand the intuition how a stable map over a tuple type works, see
// https://mmapped.blog/posts/14-stable-structures#stable-btree.
type StableMetadataMap = StableBTreeMap<(MapOwner, MapName, MapKey), PasswordMetadata, Memory>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static ENCRYPTED_MAPS: RefCell<Option<EncryptedMaps<AccessRights>>> =
        const { RefCell::new(None) };
    static METADATA: RefCell<StableMetadataMap> = RefCell::new(StableBTreeMap::new(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
    ));
}

#[init]
fn init(key_name: String) {
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: key_name,
    };
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps.replace(EncryptedMaps::init(
            "password_manager_dapp",
            key_id,
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
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
    map_owner: Principal,
    map_name: ByteBuf,
) -> Result<Vec<(Principal, AccessRights)>, String> {
    let caller = ic_cdk::api::msg_caller();
    let key_id = (
        map_owner,
        Blob::try_from(map_name.as_ref()).map_err(|_e| "name too long")?,
    );
    ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_shared_user_access_for_map(caller, key_id)
    })
}

#[query]
fn get_encrypted_values_for_map_with_metadata(
    map_owner: Principal,
    map_name: ByteBuf,
) -> Result<Vec<(ByteBuf, EncryptedMapValue, PasswordMetadata)>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    let encrypted_values_result = ENCRYPTED_MAPS.with_borrow(|encrypted_maps| {
        encrypted_maps
            .as_ref()
            .unwrap()
            .get_encrypted_values_for_map(ic_cdk::api::msg_caller(), map_id)
    });
    encrypted_values_result.map(|map_values| {
        METADATA.with_borrow(|metadata| {
            let iter_metadata = metadata
                .range((map_owner, map_name, Blob::default())..)
                .take_while(|((owner, name, _), _)| owner == &map_owner && name == &map_name)
                .map(|((_, _, key), metadata)| (key, metadata));

            iter_metadata
                .zip(map_values)
                .map(|((key_left, metadata), (key_right, encrypted_value))| {
                    debug_assert_eq!(key_left, key_right);
                    (
                        EncryptedMapValue::from(key_left.as_slice().to_vec()),
                        encrypted_value,
                        metadata,
                    )
                })
                .collect()
        })
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
fn insert_encrypted_value_with_metadata(
    map_owner: Principal,
    map_name: ByteBuf,
    map_key: ByteBuf,
    value: EncryptedMapValue,
    tags: Vec<String>,
    url: String,
) -> Result<Option<(EncryptedMapValue, PasswordMetadata)>, String> {
    let caller = ic_cdk::api::msg_caller();
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    let map_key = bytebuf_to_blob(map_key)?;
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps
            .as_mut()
            .unwrap()
            .insert_encrypted_value(caller, map_id, map_key, value)
            .map(|opt_prev_value| {
                METADATA.with_borrow_mut(|metadata| {
                    let metadata_key = (map_owner, map_name, map_key);
                    let metadata_value = metadata
                        .get(&metadata_key)
                        .map(|m| m.update(caller, tags.clone(), url.clone()))
                        .unwrap_or(PasswordMetadata::new(caller, tags, url));
                    opt_prev_value.zip(metadata.insert(metadata_key, metadata_value))
                })
            })
    })
}

#[update]
fn remove_encrypted_value_with_metadata(
    map_owner: Principal,
    map_name: ByteBuf,
    map_key: ByteBuf,
) -> Result<Option<(EncryptedMapValue, PasswordMetadata)>, String> {
    let map_name = bytebuf_to_blob(map_name)?;
    let map_id = (map_owner, map_name);
    let map_key = bytebuf_to_blob(map_key)?;
    ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
        encrypted_maps
            .as_mut()
            .unwrap()
            .remove_encrypted_value(ic_cdk::api::msg_caller(), map_id, map_key)
            .map(|opt_prev_value| {
                METADATA.with_borrow_mut(|metadata| {
                    let metadata_key = (map_owner, map_name, map_key);
                    opt_prev_value.zip(metadata.remove(&metadata_key))
                })
            })
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

ic_cdk::export_candid!();
