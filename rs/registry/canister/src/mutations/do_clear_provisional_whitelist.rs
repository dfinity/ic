use crate::{
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use ic_protobuf::registry::provisional_whitelist::v1::{
    provisional_whitelist, ProvisionalWhitelist,
};
use ic_registry_keys::make_provisional_whitelist_record_key;
use ic_registry_transport::{pb::v1::RegistryValue, upsert};

impl Registry {
    /// Clears the provisional whitelist. If no principals exist in the
    /// whitelist, this is a no-op.
    pub fn do_clear_provisional_whitelist(&mut self) {
        // Retrieve the provisional whitelist along with the current registry version.
        let mut provisional_whitelist = match self.get(
            make_provisional_whitelist_record_key().as_bytes(),
            self.latest_version(),
        ) {
            Some(RegistryValue {
                value,
                version: _,
                deletion_marker: _,
            }) => decode_registry_value::<ProvisionalWhitelist>(value.clone()),
            None => panic!("Provisional whitelist not found in the registry"),
        };

        // Set to empty list.
        provisional_whitelist.list_type = provisional_whitelist::ListType::Set.into();
        provisional_whitelist.set = vec![];

        let mutations = vec![upsert(
            make_provisional_whitelist_record_key().as_bytes(),
            encode_or_panic(&provisional_whitelist),
        )];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}
