//! See [`EncryptedMaps`] for the main documentation.

use candid::Principal;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use serde::Deserialize;
use std::future::Future;

use crate::key_manager::KeyId;
use crate::types::{
    AccessControl, ByteBuf, EncryptedMapValue, MapId, MapKey, MapName, TransportKey,
};
use ic_cdk::management_canister::VetKDKeyId;

pub type VetKeyVerificationKey = ByteBuf;
pub type VetKey = ByteBuf;

type Memory = VirtualMemory<DefaultMemoryImpl>;

/// The **EncryptedMaps** backend is a support library built on top of [`crate::key_manager::KeyManager`].
///
/// **EncryptedMaps** is designed to facilitate secure, encrypted data sharing between users on the Internet Computer (ICP) using the **vetKeys** feature. It allows developers to store encrypted key-value pairs (**maps**) securely and to manage fine-grained user access.
///
/// For an introduction to **vetKeys**, refer to the [vetKeys Overview](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/introduction).
///
/// ## Core Features
///
/// The **EncryptedMaps** library provides the following key functionalities:
///
/// - **Encrypted Key-Value Storage:** Securely store and manage encrypted key-value pairs within named maps.
/// - **User-Specific Map Access:** Control precisely which users can read or modify entries in an encrypted map.
/// - **Integrated Access Control:** Leverages the **KeyManager** library to manage and enforce user permissions.
/// - **Stable Storage:** Utilizes **[StableBTreeMap](https://crates.io/crates/ic-stable-structures)** for reliable, persistent storage across canister upgrades.
///
/// ## EncryptedMaps Architecture
///
/// The **EncryptedMaps** library contains:
///
/// - **Encrypted Values Storage:** Maps `(KeyId, MapKey)` to `EncryptedMapValue`, securely storing encrypted data.
/// - **KeyManager Integration:** Uses **KeyManager** to handle user permissions, ensuring authorized access to maps.
///
/// ## Example Use Case
///
/// 1. **User A** initializes an encrypted map and adds values.
/// 2. **User A** shares access to this map with **User B**.
/// 3. **User B** retrieves encrypted values securely.
/// 4. **User A** revokes **User B**'s access as necessary.
///
/// ## Security Considerations
///
/// - Encrypted values are stored securely with fine-grained access control.
/// - Access rights and permissions are strictly enforced.
/// - Data persists securely across canister upgrades through stable storage.
///
/// ## Summary
/// **EncryptedMaps** simplifies secure storage, retrieval, and controlled sharing of encrypted data on the Internet Computer, complementing the robust security and permissions management provided by **KeyManager**.
pub struct EncryptedMaps<T: AccessControl> {
    pub key_manager: crate::key_manager::KeyManager<T>,
    pub mapkey_vals: StableBTreeMap<(KeyId, MapKey), EncryptedMapValue, Memory>,
}

impl<T: AccessControl> EncryptedMaps<T> {
    /// Initializes the [`EncryptedMaps`] and the underlying [`crate::key_manager::KeyManager`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use ic_cdk::init;
    /// use ic_cdk::management_canister::{VetKDCurve, VetKDKeyId};
    /// use ic_stable_structures::{
    ///     memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    ///     DefaultMemoryImpl,
    /// };
    /// use std::cell::RefCell;
    /// use ic_vetkeys::types::AccessRights;
    /// use ic_vetkeys::encrypted_maps::EncryptedMaps;
    ///
    /// type Memory = VirtualMemory<DefaultMemoryImpl>;
    ///
    /// thread_local! {
    ///     static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
    ///         RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    ///     static ENCRYPTED_MAPS: RefCell<Option<EncryptedMaps<AccessRights>>> = const { RefCell::new(None) };
    /// }
    ///
    /// #[init]
    /// fn init(key_name: String) {
    ///     let key_id = VetKDKeyId {
    ///         curve: VetKDCurve::Bls12_381_G2,
    ///         name: key_name,
    ///     };
    ///     ENCRYPTED_MAPS.with_borrow_mut(|encrypted_maps| {
    ///         encrypted_maps.replace(EncryptedMaps::init(
    ///         "my encrypted maps dapp",
    ///         key_id,
    ///         id_to_memory(0),
    ///         id_to_memory(1),
    ///         id_to_memory(2),
    ///         id_to_memory(3),
    ///         ));
    ///     });
    /// }
    ///
    /// fn id_to_memory(id: u8) -> Memory {
    ///     MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(id)))
    /// }
    /// ```
    pub fn init(
        domain_separator: &str,
        key_id: VetKDKeyId,
        memory_domain_separator: Memory,
        memory_access_control: Memory,
        memory_shared_keys: Memory,
        memory_encrypted_maps: Memory,
    ) -> Self {
        let key_manager = crate::key_manager::KeyManager::init(
            domain_separator,
            key_id,
            memory_domain_separator,
            memory_access_control,
            memory_shared_keys,
        );

        let mapkey_vals = StableBTreeMap::init(memory_encrypted_maps);

        Self {
            key_manager,
            mapkey_vals,
        }
    }

    /// Lists all map names shared with the caller.
    /// Returns a vector of map IDs that the caller has access to.
    pub fn get_accessible_shared_map_names(&self, caller: Principal) -> Vec<KeyId> {
        self.key_manager.get_accessible_shared_key_ids(caller)
    }

    /// Retrieves all users and their access rights for a specific map.
    /// The caller must have appropriate permissions to view this information.
    pub fn get_shared_user_access_for_map(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(Principal, T)>, String> {
        self.key_manager
            .get_shared_user_access_for_key(caller, key_id)
    }

    /// Removes all values from a map if the caller has sufficient rights.
    /// Returns the removed keys.
    /// The caller must have write permissions to perform this operation.
    pub fn remove_map_values(
        &mut self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<MapKey>, String> {
        self.key_manager.ensure_user_can_write(caller, key_id)?;

        let keys: Vec<_> = self
            .mapkey_vals
            .range((key_id, Blob::default())..)
            .take_while(|entry| entry.key().0 == key_id)
            .map(|entry| entry.key().1)
            .collect();

        for key in keys.iter() {
            self.mapkey_vals.remove(&(key_id, *key));
        }

        Ok(keys)
    }

    /// Retrieves all encrypted key-value pairs from a map.
    /// The caller must have read permissions to access the map values.
    pub fn get_encrypted_values_for_map(
        &self,
        caller: Principal,
        key_id: KeyId,
    ) -> Result<Vec<(MapKey, EncryptedMapValue)>, String> {
        self.key_manager.ensure_user_can_read(caller, key_id)?;

        Ok(self
            .mapkey_vals
            .range((key_id, Blob::default())..)
            .take_while(|entry| entry.key().0 == key_id)
            .map(|entry| (entry.key().1, entry.value()))
            .collect())
    }

    /// Retrieves a specific encrypted value from a map.
    /// The caller must have read permissions to access the value.
    pub fn get_encrypted_value(
        &self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
    ) -> Result<Option<EncryptedMapValue>, String> {
        self.key_manager.ensure_user_can_read(caller, key_id)?;
        Ok(self.mapkey_vals.get(&(key_id, key)))
    }

    /// Retrieves the non-empty map names owned by the caller.
    pub fn get_all_accessible_encrypted_values(
        &self,
        caller: Principal,
    ) -> Vec<(MapId, Vec<(MapKey, EncryptedMapValue)>)> {
        let mut result = Vec::new();
        for map_id in self.get_accessible_map_ids_iter(caller) {
            let map_values = self.get_encrypted_values_for_map(caller, map_id).unwrap();
            result.push((map_id, map_values));
        }
        result
    }

    /// Retrieves all accessible encrypted maps and their data for the caller.
    pub fn get_all_accessible_encrypted_maps(&self, caller: Principal) -> Vec<EncryptedMapData<T>> {
        let mut result = Vec::new();
        for map_id in self.get_accessible_map_ids_iter(caller) {
            let keyvals = self
                .get_encrypted_values_for_map(caller, map_id)
                .unwrap()
                .into_iter()
                .map(|(key, value)| (ByteBuf::from(key.as_ref().to_vec()), value))
                .collect();
            let map = EncryptedMapData {
                map_owner: map_id.0,
                map_name: ByteBuf::from(map_id.1.as_ref().to_vec()),
                keyvals,
                access_control: self
                    .get_shared_user_access_for_map(caller, map_id)
                    .unwrap_or_default(),
            };
            result.push(map);
        }
        result
    }

    fn get_accessible_map_ids_iter(
        &self,
        caller: Principal,
    ) -> impl Iterator<Item = (Principal, MapName)> {
        let accessible_map_ids = self.get_accessible_shared_map_names(caller).into_iter();
        let owned_map_ids =
            std::iter::repeat(caller).zip(self.get_owned_non_empty_map_names(caller));
        accessible_map_ids.chain(owned_map_ids)
    }

    /// Retrieves the non-empty map names owned by the caller.
    /// Returns a list of map names that contain at least one key-value pair.
    pub fn get_owned_non_empty_map_names(&self, caller: Principal) -> Vec<MapName> {
        let map_names: std::collections::HashSet<Vec<u8>> = self
            .mapkey_vals
            .keys_range(((caller, Blob::default()), Blob::default())..)
            .take_while(|((principal, _map_name), _key_name)| principal == &caller)
            .map(|((_principal, map_name), _key_name)| map_name.as_slice().to_vec())
            .collect();
        map_names
            .into_iter()
            .map(|map_name| Blob::<32>::try_from(map_name.as_slice()).unwrap())
            .collect()
    }

    /// Inserts or updates an encrypted value in a map.
    /// The caller must have write permissions to modify the map.
    pub fn insert_encrypted_value(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
        encrypted_value: EncryptedMapValue,
    ) -> Result<Option<EncryptedMapValue>, String> {
        self.key_manager.ensure_user_can_write(caller, key_id)?;
        Ok(self.mapkey_vals.insert((key_id, key), encrypted_value))
    }

    /// Removes an encrypted value from a map.
    /// The caller must have write permissions to modify the map.
    pub fn remove_encrypted_value(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        key: MapKey,
    ) -> Result<Option<EncryptedMapValue>, String> {
        self.key_manager.ensure_user_can_write(caller, key_id)?;
        Ok(self.mapkey_vals.remove(&(key_id, key)))
    }

    /// Retrieves the public verification key from KeyManager.
    /// This key is used to verify the authenticity of derived keys.
    pub fn get_vetkey_verification_key(
        &self,
    ) -> impl Future<Output = VetKeyVerificationKey> + Send + Sync {
        self.key_manager.get_vetkey_verification_key()
    }

    /// Retrieves an encrypted vetkey for caller and key id.
    /// The key is secured using the provided transport key and can only be accessed by authorized users.
    pub fn get_encrypted_vetkey(
        &self,
        caller: Principal,
        key_id: KeyId,
        transport_key: TransportKey,
    ) -> Result<impl Future<Output = VetKey> + Send + Sync, String> {
        self.key_manager
            .get_encrypted_vetkey(caller, key_id, transport_key)
    }

    /// Retrieves access rights for a user to a map.
    /// The caller must have appropriate permissions to view this information.
    pub fn get_user_rights(
        &self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<T>, String> {
        self.key_manager.get_user_rights(caller, key_id, user)
    }

    /// Sets or updates access rights for a user to a map.
    /// Only the map owner or a user with management rights can perform this action.
    pub fn set_user_rights(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
        access_rights: T,
    ) -> Result<Option<T>, String> {
        self.key_manager
            .set_user_rights(caller, key_id, user, access_rights)
    }

    /// Removes access rights for a user from a map.
    /// Only the map owner or a user with management rights can perform this action.
    pub fn remove_user(
        &mut self,
        caller: Principal,
        key_id: KeyId,
        user: Principal,
    ) -> Result<Option<T>, String> {
        self.key_manager.remove_user(caller, key_id, user)
    }
}

/// Represents the complete data for an encrypted map, including ownership, contents, and access control.
#[derive(candid::CandidType, Deserialize)]
pub struct EncryptedMapData<T: AccessControl> {
    pub map_owner: Principal,
    pub map_name: ByteBuf,
    pub keyvals: Vec<(ByteBuf, EncryptedMapValue)>,
    pub access_control: Vec<(Principal, T)>,
}
