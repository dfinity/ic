use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::export::candid::candid_method;
use ic_certified_blockchain_lib::{Blob, Block, Callers, Data, HashTree, LookupResult};
use ic_certified_map::{AsHashTree, Hash, RbTree};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log, storable::Blob as StorableBlob, BoundedStorable,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use num::FromPrimitive;
use prost::Message;
use serde::Serialize;
use sha2::Digest;
use std::{borrow::Cow, cell::RefCell, convert::TryInto, fmt::Debug, str::FromStr, time::Duration};

#[macro_use]
extern crate num_derive;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type BlockTree = RbTree<Blob, Hash>;

const UPDATE_PERMISSIONS_EVERY_SECS: u64 = 3600; // 1 hour

#[derive(Clone, Debug, CandidType, Deserialize, FromPrimitive)]
enum Auth {
    User,
    Admin,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Authorization {
    id: Principal,
    auth: Auth,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Metadata {
    previous_hash: Hash,
    base_index: u64,
    b_is_primary: bool,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize, Ord, PartialEq, PartialOrd, Eq)]
struct BlobHash(Hash);

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Pending {
    data: Data,
    callers: Callers,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ReplicaCertificate {
    tree: HashTree<'static>,
    signature: serde_bytes::ByteBuf,
}

impl Storable for BlobHash {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let mut hash = [0; 32];
        hash[..32].copy_from_slice(&bytes[..32]);
        BlobHash(hash)
    }
}
impl BoundedStorable for BlobHash {
    const MAX_SIZE: u32 = 32;
    const IS_FIXED_SIZE: bool = false;
}
impl Storable for Pending {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}
impl Storable for Metadata {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static METADATA: RefCell<StableCell<Metadata, Memory>> = RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            <Metadata>::default()).unwrap());
    static LOGA: RefCell<Log<Vec<u8>, Memory, Memory>> = RefCell::new(
        Log::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        ).unwrap()
    );
    static LOGB: RefCell<Log<Vec<u8>, Memory, Memory>> = RefCell::new(
        Log::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
        ).unwrap()
    );
    static MAPA: RefCell<StableBTreeMap<BlobHash, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))),
        )
    );
    static MAPB: RefCell<StableBTreeMap<BlobHash, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6))),
        )
    );
    static PENDING: RefCell<StableCell<Pending, Memory>> = RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(7))),
            Pending::default()).unwrap());
    static AUTH: RefCell<StableBTreeMap<StorableBlob<29>, u32, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(8))),
            )
        );
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn prepare(data: Data) -> Blob {
    if PENDING.with(|p| p.borrow().get().data.len()) > 0 {
        ic_cdk::trap("Block already prepared");
    }
    prepare_some(data)
}

fn hash_pending(pending: &Pending, i: usize) -> [u8; 32] {
    let caller_hash: [u8; 32] = sha2::Sha256::digest(pending.callers[i]).into();
    let data_hash: [u8; 32] = sha2::Sha256::digest(pending.data[i].clone()).into();
    let mut hasher = sha2::Sha256::new();
    hasher.update(caller_hash);
    hasher.update(data_hash);
    let hash: [u8; 32] = hasher.finalize().into();
    hash
}

fn build_tree(pending: &Pending, previous_hash: &Hash) -> BlockTree {
    let mut tree = BlockTree::default();
    for (i, _) in pending.data.iter().enumerate() {
        tree.insert(i.to_be_bytes().to_vec(), hash_pending(pending, i));
    }
    tree.insert("previous_hash".as_bytes().to_vec(), *previous_hash); // For lexigraphic order.
    tree
}

fn take_cell<T>(c: &mut StableCell<T, Memory>) -> T
where
    T: Clone + Default + Storable,
{
    let v = c.get().clone();
    c.set(T::default()).unwrap();
    v
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn prepare_some(new_data: Data) -> Blob {
    let mut pending = PENDING.with(|d| take_cell(&mut d.borrow_mut()));
    for d in new_data.iter() {
        pending.data.push(d.to_vec());
        pending.callers.push(ic_cdk::caller());
    }
    let previous_hash = get_previous_hash();
    let tree = build_tree(&pending, &previous_hash);
    PENDING.with(|p| {
        p.borrow_mut().set(pending).unwrap();
    });
    set_certificate(&tree.root_hash())
}

fn set_certificate(root_hash: &Hash) -> Blob {
    let certified_data = &ic_certified_map::labeled_hash(b"certified_blocks", root_hash);
    ic_cdk::api::set_certified_data(certified_data);
    certified_data.to_vec()
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn get_certificate() -> Option<Blob> {
    if PENDING.with(|p| p.borrow().get().data.len()) == 0 {
        None
    } else {
        ic_cdk::api::data_certificate()
    }
}

fn get_previous_hash() -> Hash {
    let mut previous_hash = METADATA.with(|h| h.borrow().get().previous_hash);
    primary_log().with(|l| {
        let l = l.borrow();
        if l.len() > 0 {
            previous_hash =
                sha2::Sha256::digest(Encode!(&l.get(l.len() - 1).unwrap()).unwrap()).into();
        }
    });
    previous_hash
}

fn primary_map() -> &'static std::thread::LocalKey<RefCell<StableBTreeMap<BlobHash, u64, Memory>>> {
    if METADATA.with(|m| m.borrow().get().b_is_primary) {
        &MAPB
    } else {
        &MAPA
    }
}

fn primary_log() -> &'static std::thread::LocalKey<RefCell<Log<Vec<u8>, Memory, Memory>>> {
    if METADATA.with(|m| m.borrow().get().b_is_primary) {
        &LOGB
    } else {
        &LOGA
    }
}

fn secondary_log() -> &'static std::thread::LocalKey<RefCell<Log<Vec<u8>, Memory, Memory>>> {
    if METADATA.with(|m| m.borrow().get().b_is_primary) {
        &LOGA
    } else {
        &LOGB
    }
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn commit(certificate: Blob) -> Option<u64> {
    let pending = PENDING.with(|p| take_cell(&mut p.borrow_mut()));
    if pending.data.is_empty() {
        return None;
    }
    let previous_hash = get_previous_hash();
    let tree = build_tree(&pending, &previous_hash);
    // Check that the certificate corresponds to our tree.  Note: we are
    // not fully verifying the certificate, just checking for races.
    let root_hash = tree.root_hash();
    let certified_data = &ic_certified_map::labeled_hash(b"certified_blocks", &root_hash);
    let cert: ReplicaCertificate = serde_cbor::from_slice(&certificate[..]).unwrap();
    let canister_id = ic_cdk::api::id();
    let canister_id = canister_id.as_slice();
    if let LookupResult::Found(certified_data_bytes) = cert.tree.lookup_path(&[
        "canister".into(),
        canister_id.into(),
        "certified_data".into(),
    ]) {
        assert!(certified_data == certified_data_bytes);
    } else {
        ic_cdk::trap("certificate mismatch");
    }
    let index = next();
    primary_map().with(|m| {
        let mut m = m.borrow_mut();
        for (_, h) in tree.iter() {
            m.insert(BlobHash(*h), index).unwrap();
        }
        for d in pending.data.iter() {
            let hash = sha2::Sha256::digest(d).into();
            m.insert(BlobHash(hash), index).unwrap();
        }
    });
    primary_log().with(|l| {
        let l = l.borrow_mut();
        let hash_tree = ic_certified_map::labeled(b"certified_blocks", tree.as_hash_tree());
        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        hash_tree.serialize(&mut serializer).unwrap();
        let block = Block {
            certificate,
            tree: serializer.into_inner(),
            data: pending.data,
            callers: pending.callers,
            previous_hash,
        };
        let encoded_block = Encode!(&block).unwrap();
        l.append(&encoded_block).unwrap();
    });
    Some(next() - 1)
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn get_block(index: u64) -> Block {
    if index < first() {
        ic_cdk::trap("index before first()");
    }
    let index = index - first();
    let secondary_len = secondary_log().with(|l| l.borrow().len());
    if index < secondary_len {
        secondary_log().with(|l| {
            candid::decode_one(
                &l.borrow()
                    .get((index as usize).try_into().unwrap())
                    .unwrap(),
            )
            .unwrap()
        })
    } else {
        let index = index - secondary_len;
        primary_log().with(|l| {
            candid::decode_one(
                &l.borrow()
                    .get((index as usize).try_into().unwrap())
                    .unwrap(),
            )
            .unwrap()
        })
    }
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn find(hash: Hash) -> Option<u64> {
    if let Some(index) = MAPA.with(|m| m.borrow().get(&BlobHash(hash))) {
        Some(index)
    } else {
        MAPB.with(|m| m.borrow().get(&BlobHash(hash)))
    }
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn first() -> u64 {
    METADATA.with(|m| m.borrow().get().base_index)
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn mid() -> u64 {
    METADATA.with(|m| m.borrow().get().base_index) + secondary_log().with(|l| l.borrow().len())
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn next() -> u64 {
    METADATA.with(|m| m.borrow().get().base_index)
        + LOGA.with(|l| l.borrow().len())
        + LOGB.with(|l| l.borrow().len())
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn last_hash() -> String {
    if primary_log().with(|l| l.borrow().len()) != 0 {
        log_hash(primary_log())
    } else {
        log_hash(secondary_log())
    }
}

fn log_hash(log: &'static std::thread::LocalKey<RefCell<Log<Vec<u8>, Memory, Memory>>>) -> String {
    log.with(|l| {
        let l = l.borrow();
        if l.len() == 0 {
            return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }
        let previous_hash: [u8; 32] =
            sha2::Sha256::digest(Encode!(&l.get(l.len() - 1).unwrap()).unwrap()).into();
        hex::encode(previous_hash)
    })
}

#[ic_cdk_macros::update(guard = "is_authorized_user")]
#[candid_method]
fn rotate() -> Option<u64> {
    let mut metadata = METADATA.with(|m| m.borrow().get().clone());
    let old_base_index = metadata.base_index;
    LOGA.with(|loga| {
        LOGB.with(|logb| {
            MAPA.with(|mapa| {
                MAPB.with(|mapb| {
                    if !metadata.b_is_primary {
                        metadata.base_index += logb.borrow().len();
                        logb.replace(Log::new(
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
                        ));
                        mapb.replace(StableBTreeMap::new(
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6))),
                        ));
                    } else {
                        metadata.base_index += loga.borrow().len();
                        loga.replace(Log::new(
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
                        ));
                        mapa.replace(StableBTreeMap::new(
                            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))),
                        ));
                    }
                });
            });
        });
    });
    metadata.b_is_primary = !metadata.b_is_primary;
    METADATA.with(|m| m.borrow_mut().set(metadata.clone()).unwrap());
    if metadata.base_index != old_base_index {
        Some(metadata.base_index)
    } else {
        None
    }
}

#[derive(Deserialize, PartialEq, Message)]
struct SubnetListRecord {
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub subnets: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}

#[derive(Deserialize, Message)]
struct SubnetRecord {
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub membership: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct RegistryGetValueRequest {
    #[prost(message, optional, tag = "1")]
    pub version: ::core::option::Option<u64>,
    #[prost(bytes = "vec", tag = "2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct RegistryGetValueResponse {
    #[prost(bytes = "vec", tag = "3")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}

pub fn make_get_value_request(key: &str) -> Vec<u8> {
    let request = RegistryGetValueRequest {
        key: key.as_bytes().to_vec(),
        version: None,
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();
    buf
}

async fn update_permissions_from_registry() {
    let registry_canister =
        Principal::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").expect("Failed to create principal");
    let subnets = ic_cdk::api::call::call_raw(
        registry_canister,
        "get_value",
        &make_get_value_request("subnet_list"),
        0,
    )
    .await
    .unwrap();
    let subnets = RegistryGetValueResponse::decode(subnets.as_slice()).unwrap();
    let subnets = SubnetListRecord::decode(subnets.value.as_slice()).unwrap();
    let subnets: Vec<Principal> = subnets
        .subnets
        .iter()
        .map(|subnet_id_vec| Principal::from_slice(subnet_id_vec))
        .collect();
    for s in subnets {
        let members = ic_cdk::api::call::call_raw(
            registry_canister,
            "get_value",
            &make_get_value_request(&format!("subnet_record_{}", s)),
            0,
        )
        .await
        .unwrap();
        let members = RegistryGetValueResponse::decode(members.as_slice()).unwrap();
        let members = SubnetRecord::decode(members.value.as_slice()).unwrap();
        for node in members.membership {
            authorize_principal(&Principal::from_slice(node.as_slice()), Auth::User);
        }
    }
}

fn start_tasks() {
    ic_cdk_timers::set_timer_interval(Duration::from_secs(UPDATE_PERMISSIONS_EVERY_SECS), || {
        ic_cdk::spawn(update_permissions_from_registry())
    });
}

#[ic_cdk_macros::init]
fn canister_init(previous_hash: Option<String>) {
    authorize_principal(&ic_cdk::caller(), Auth::Admin);
    if let Some(previous_hash) = previous_hash {
        let _x = hex::decode(&previous_hash).unwrap();
        if let Ok(previous_hash) = hex::decode(&previous_hash) {
            if previous_hash.len() == 32 {
                METADATA.with(|m| {
                    let mut metadata = m.borrow().get().clone();
                    metadata.previous_hash = previous_hash.as_slice().try_into().unwrap();
                    m.borrow_mut().set(metadata).unwrap();
                });
                return;
            }
        }
        ic_cdk::trap("previous must be a 64 hex string");
    }
    start_tasks();
}

#[ic_cdk_macros::query]
#[candid_method(query)]
fn get_authorized() -> Vec<Authorization> {
    let mut authorized = Vec::<Authorization>::new();
    AUTH.with(|a| {
        for (k, v) in a.borrow().iter() {
            if let Some(auth) = Auth::from_i32(v as i32) {
                authorized.push(Authorization {
                    id: Principal::from_slice(&k.to_bytes()),
                    auth,
                });
            }
        }
    });
    authorized
}

#[ic_cdk_macros::update(guard = "is_authorized_admin")]
#[candid_method]
fn authorize(principal: Principal, value: Auth) {
    authorize_principal(&principal, value);
}

#[ic_cdk_macros::update(guard = "is_authorized_admin")]
#[candid_method]
fn deauthorize(principal: Principal) {
    AUTH.with(|a| {
        a.borrow_mut()
            .remove(&StorableBlob::from_bytes(principal.as_slice().into()))
            .unwrap();
    });
}

fn authorize_principal(principal: &Principal, value: Auth) {
    AUTH.with(|a| {
        a.borrow_mut()
            .insert(
                StorableBlob::from_bytes(principal.as_slice().into()),
                value as u32,
            )
            .unwrap();
    });
}

fn is_authorized_user() -> Result<(), String> {
    AUTH.with(|a| {
        if a.borrow().contains_key(&StorableBlob::from_bytes(
            ic_cdk::caller().as_slice().into(),
        )) {
            Ok(())
        } else {
            Err("is_authorized_user(): You are not authorized.".to_string())
        }
    })
}

fn is_authorized_admin() -> Result<(), String> {
    AUTH.with(|a| {
        if let Some(value) = a.borrow().get(&StorableBlob::from_bytes(
            ic_cdk::caller().as_slice().into(),
        )) {
            if value >= Auth::Admin as u32 {
                Ok(())
            } else {
                Err("is_authorized_admin(): You are not authorized as Admin".to_string())
            }
        } else {
            Err("is_authorized_admin(): You are not authorized".to_string())
        }
    })
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    let previous_hash = get_previous_hash();
    let tree = PENDING.with(|p| build_tree(p.borrow().get(), &previous_hash));
    set_certificate(&tree.root_hash());
    start_tasks();
}

ic_cdk::export::candid::export_service!();

#[ic_cdk_macros::query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    __export_service()
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    println!("{}", export_candid());
}

#[cfg(target_arch = "wasm32")]
fn main() {}
