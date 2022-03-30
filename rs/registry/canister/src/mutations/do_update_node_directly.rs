use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use prost::Message;

use candid::{CandidType, Deserialize};
use ic_base_types::NodeId;
use ic_crypto_node_key_validation::ValidIDkgDealingEncryptionPublicKey;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_keys::{make_crypto_node_key, make_node_record_key};
use ic_registry_transport::insert;
use ic_types::crypto::KeyPurpose;

impl Registry {
    /// Updates an existing node's config in the registry.
    ///
    /// This method is called directly by the node itself that needs to update its node record.
    pub fn do_update_node_directly(
        &mut self,
        payload: UpdateNodeDirectlyPayload,
    ) -> Result<(), String> {
        println!("{}do_update_node_directly: {:?}", LOG_PREFIX, payload);

        // 1. Sanity check payload is not empty
        if let Some(idkg_dealing_encryption_pk) = &payload.idkg_dealing_encryption_pk {
            if idkg_dealing_encryption_pk.is_empty() {
                return Err(String::from("idkg_dealing_encryption_pk is empty"));
            }
        } else {
            return Err(String::from("idkg_dealing_encryption_pk is missing"));
        }

        // 2. Check pk is not malformed
        let idkg_dealing_encryption_pk = PublicKey::decode(
            &payload
                .idkg_dealing_encryption_pk
                .as_ref()
                .map_or(&vec![], |v| v)[..],
        )
        .map_err(|e| {
            format!(
                "idkg_dealing_encryption_pk is not in the expected format: {:?}",
                e
            )
        })?;

        // 3. Check that caller is a node with a node_id that exists
        let caller = dfn_core::api::caller();
        let node_id = NodeId::from(caller);

        let node_key = make_node_record_key(node_id);
        self
            .get(&node_key.as_bytes().to_vec(), self.latest_version())
            .ok_or_else(|| format!(
            "{}do_update_node_directly: Node Id {:} not found in the registry, aborting node update.",
            LOG_PREFIX, node_id))?;

        // 4. Disallow updating if a key has already been set
        let idkg_de_pk_key = make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption);
        if self
            .get(&idkg_de_pk_key.as_bytes().to_vec(), self.latest_version())
            .is_some()
        {
            return Err(format!(
                "I-DKG key was already set for this node {:?}",
                idkg_de_pk_key
            ));
        }

        // 5. Validate the I-DKG dealing encryption public key
        let valid_idkg_dealing_encryption_pk =
            ValidIDkgDealingEncryptionPublicKey::try_from(idkg_dealing_encryption_pk)
                .map_err(|e| format!("{}", e))?;

        // 6. Create and apply mutation for new record
        let insert_idkg_key = insert(
            idkg_de_pk_key.as_bytes().to_vec(),
            encode_or_panic(valid_idkg_dealing_encryption_pk.get()),
        );

        let mutations = vec![insert_idkg_key];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        Ok(())
    }
}

/// The payload of an request to update keys of the existing node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeDirectlyPayload {
    pub idkg_dealing_encryption_pk: Option<Vec<u8>>,
}
