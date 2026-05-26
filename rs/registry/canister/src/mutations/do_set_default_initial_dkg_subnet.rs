use crate::{common::LOG_PREFIX, registry::Registry};

use candid::CandidType;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::types::v1::{PrincipalId as PrincipalIdProto, SubnetId as SubnetIdProto};
use ic_registry_keys::DEFAULT_INITIAL_DKG_SUBNET_ID_KEY;
use ic_registry_transport::{delete, upsert};
use prost::Message;
use serde::{Deserialize, Serialize};

impl Registry {
    /// Sets (or removes, if `subnet_id` is `None`) the default subnet to which
    /// `SetupInitialDKG` management canister calls are routed when no subnet
    /// is specified explicitly in the request.
    pub fn do_set_default_initial_dkg_subnet(
        &mut self,
        payload: SetDefaultInitialDkgSubnetPayload,
    ) {
        println!("{LOG_PREFIX}do_set_default_initial_dkg_subnet: {payload:?}");
        self.validate_set_default_initial_dkg_subnet(&payload)
            .unwrap_or_else(|err| {
                panic!("{LOG_PREFIX}do_set_default_initial_dkg_subnet validation failed: {err}")
            });

        let mutation = match payload.subnet_id() {
            Some(subnet_id) => {
                let subnet_id_proto = SubnetIdProto {
                    principal_id: Some(PrincipalIdProto {
                        raw: subnet_id.get().into_vec(),
                    }),
                };
                upsert(
                    DEFAULT_INITIAL_DKG_SUBNET_ID_KEY.as_bytes(),
                    subnet_id_proto.encode_to_vec(),
                )
            }
            None => delete(DEFAULT_INITIAL_DKG_SUBNET_ID_KEY.as_bytes()),
        };

        self.maybe_apply_mutation_internal(vec![mutation]);
    }

    fn validate_set_default_initial_dkg_subnet(
        &self,
        payload: &SetDefaultInitialDkgSubnetPayload,
    ) -> Result<(), String> {
        // If a subnet id is set, it must refer to an existing subnet.
        if let Some(subnet_id) = payload.subnet_id() {
            self.get_subnet(subnet_id, self.latest_version())
                .map_err(|err| {
                    format!("subnet_id {subnet_id} does not refer to an existing subnet: {err}")
                })?;
        }

        // If we are removing the entry, ensure it currently exists; otherwise
        // the proposal is a no-op.
        if payload.subnet_id.is_none()
            && self
                .get(
                    DEFAULT_INITIAL_DKG_SUBNET_ID_KEY.as_bytes(),
                    self.latest_version(),
                )
                .is_none()
        {
            return Err(
                "no default initial DKG subnet is currently configured; nothing to remove."
                    .to_string(),
            );
        }

        Ok(())
    }
}

/// Payload of a proposal to set or unset the default subnet to which
/// `SetupInitialDKG` management canister calls are routed when no subnet is
/// specified explicitly in the request.
///
/// If `subnet_id` is `Some(_)`, the registry entry is created or updated to
/// point at the given subnet; if `subnet_id` is `None`, the registry entry is
/// removed and `SetupInitialDKG` requests fall back to being routed to the
/// calling subnet (NNS).
#[derive(Debug, Clone, Eq, PartialEq, CandidType, Serialize, Deserialize)]
pub struct SetDefaultInitialDkgSubnetPayload {
    pub subnet_id: Option<PrincipalId>,
}

impl SetDefaultInitialDkgSubnetPayload {
    /// Returns the subnet id wrapped as [`SubnetId`], if any.
    pub fn subnet_id(&self) -> Option<SubnetId> {
        self.subnet_id.map(SubnetId::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use ic_base_types::NodeId;
    use ic_test_utilities_types::ids::subnet_test_id;
    use lazy_static::lazy_static;
    use maplit::btreemap;

    lazy_static! {
        static ref SUBNET_ID: SubnetId = subnet_test_id(2000);
        static ref _FIXTURE: (Registry, NodeId) = {
            let mut registry = invariant_compliant_registry(0);
            let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
                1, // start_mutation_id
                1, // nodes
            );
            registry.maybe_apply_mutation_internal(mutate_request.mutations);

            let (node_id, dkg_pk) = node_ids_and_dkg_pks
                .iter()
                .next()
                .expect("should contain at least one node ID");
            let node_id = *node_id;

            let mut subnet_list_record = registry.get_subnet_list_record();
            let subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
            registry.maybe_apply_mutation_internal(add_fake_subnet(
                *SUBNET_ID,
                &mut subnet_list_record,
                subnet_record,
                &btreemap!(node_id => dkg_pk.clone()),
            ));

            (registry, node_id)
        };
        static ref REGISTRY: Registry = _FIXTURE.0.clone();
    }

    fn registry_value(registry: &Registry) -> Option<SubnetId> {
        let registry_value = registry.get(
            DEFAULT_INITIAL_DKG_SUBNET_ID_KEY.as_bytes(),
            registry.latest_version(),
        )?;
        let proto = SubnetIdProto::decode(registry_value.value.as_slice()).unwrap();
        let principal_id_proto = proto.principal_id?;
        Some(SubnetId::from(
            PrincipalId::try_from(principal_id_proto.raw).unwrap(),
        ))
    }

    #[test]
    fn test_set_default_initial_dkg_subnet_sets_value() {
        let mut registry = REGISTRY.clone();

        assert_eq!(registry_value(&registry), None);

        registry.do_set_default_initial_dkg_subnet(SetDefaultInitialDkgSubnetPayload {
            subnet_id: Some(SUBNET_ID.get()),
        });

        assert_eq!(registry_value(&registry), Some(*SUBNET_ID));

        registry.do_set_default_initial_dkg_subnet(SetDefaultInitialDkgSubnetPayload {
            subnet_id: None,
        });

        assert_eq!(registry_value(&registry), None);
    }

    #[test]
    #[should_panic(expected = "does not refer to an existing subnet")]
    fn test_set_default_initial_dkg_subnet_unknown_subnet_panics() {
        let mut registry = REGISTRY.clone();

        let unknown_subnet_id = subnet_test_id(123456789);
        registry.do_set_default_initial_dkg_subnet(SetDefaultInitialDkgSubnetPayload {
            subnet_id: Some(unknown_subnet_id.get()),
        });
    }

    #[test]
    #[should_panic(expected = "no default initial DKG subnet is currently configured")]
    fn test_set_default_initial_dkg_subnet_unset_when_unset_panics() {
        let mut registry = REGISTRY.clone();

        registry.do_set_default_initial_dkg_subnet(SetDefaultInitialDkgSubnetPayload {
            subnet_id: None,
        });
    }
}
