use crate::{
    mutations::{do_create_subnet::CanisterCyclesCostSchedule, do_update_subnet::ChainKeyConfig},
    registry::Registry,
};
use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::{
    CanisterCyclesCostSchedule as CanisterCyclesCostSchedulePb, ResourceLimits, SubnetFeatures,
    SubnetRecord as SubnetRecordPb,
};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_features::ChainKeyConfig as ChainKeyConfigInternal;
use ic_registry_subnet_type::SubnetType;
use prost::Message;
use serde::Serialize;

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct GetSubnetRequest {
    pub subnet_id: Option<PrincipalId>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SubnetRecord {
    pub membership: Vec<Vec<u8>>,
    pub max_ingress_bytes_per_message: u64,
    pub unit_delay_millis: u64,
    pub initial_notary_delay_millis: u64,
    pub replica_version_id: String,
    pub dkg_interval_length: u64,
    pub start_as_nns: bool,
    pub subnet_type: SubnetType,
    pub dkg_dealings_per_block: u64,
    pub is_halted: bool,
    pub max_ingress_messages_per_block: u64,
    pub max_ingress_bytes_per_block: u64,
    pub max_block_payload_size: u64,
    pub features: Option<SubnetFeatures>,
    pub max_number_of_canisters: u64,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,
    pub halt_at_cup_height: bool,
    pub chain_key_config: Option<ChainKeyConfig>,
    pub canister_cycles_cost_schedule: CanisterCyclesCostSchedule,
    pub subnet_admins: Vec<PrincipalId>,
    pub recalled_replica_version_ids: Vec<String>,
    pub resource_limits: Option<ResourceLimits>,
}

impl TryFrom<SubnetRecordPb> for SubnetRecord {
    type Error = String;

    fn try_from(pb: SubnetRecordPb) -> Result<Self, Self::Error> {
        let subnet_type = SubnetType::try_from(pb.subnet_type)
            .map_err(|e| format!("Invalid subnet_type: {e}"))?;

        let cost_schedule_pb =
            CanisterCyclesCostSchedulePb::try_from(pb.canister_cycles_cost_schedule)
                .unwrap_or(CanisterCyclesCostSchedulePb::Unspecified);
        let canister_cycles_cost_schedule = match cost_schedule_pb {
            CanisterCyclesCostSchedulePb::Free => CanisterCyclesCostSchedule::Free,
            _ => CanisterCyclesCostSchedule::Normal,
        };

        let chain_key_config = pb
            .chain_key_config
            .map(|c| {
                ChainKeyConfigInternal::try_from(c)
                    .map(ChainKeyConfig::from)
                    .map_err(|e| format!("Invalid chain_key_config: {e}"))
            })
            .transpose()?;

        let subnet_admins = pb
            .subnet_admins
            .into_iter()
            .map(PrincipalId::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid subnet_admins: {e}"))?;

        Ok(SubnetRecord {
            membership: pb.membership,
            max_ingress_bytes_per_message: pb.max_ingress_bytes_per_message,
            unit_delay_millis: pb.unit_delay_millis,
            initial_notary_delay_millis: pb.initial_notary_delay_millis,
            replica_version_id: pb.replica_version_id,
            dkg_interval_length: pb.dkg_interval_length,
            start_as_nns: pb.start_as_nns,
            subnet_type,
            dkg_dealings_per_block: pb.dkg_dealings_per_block,
            is_halted: pb.is_halted,
            max_ingress_messages_per_block: pb.max_ingress_messages_per_block,
            max_ingress_bytes_per_block: pb.max_ingress_bytes_per_block,
            max_block_payload_size: pb.max_block_payload_size,
            features: pb.features,
            max_number_of_canisters: pb.max_number_of_canisters,
            ssh_readonly_access: pb.ssh_readonly_access,
            ssh_backup_access: pb.ssh_backup_access,
            halt_at_cup_height: pb.halt_at_cup_height,
            chain_key_config,
            canister_cycles_cost_schedule,
            subnet_admins,
            recalled_replica_version_ids: pb.recalled_replica_version_ids,
            resource_limits: pb.resource_limits,
        })
    }
}

impl Registry {
    pub fn get_subnet_record(&self, request: GetSubnetRequest) -> Result<SubnetRecord, String> {
        let subnet_id = request
            .subnet_id
            .ok_or_else(|| "No subnet_id supplied".to_string())?;

        let key = make_subnet_record_key(SubnetId::from(subnet_id));
        let record_bytes = self
            .get(key.as_bytes(), self.latest_version())
            .ok_or_else(|| format!("Subnet {subnet_id} not found in the Registry"))?
            .value;

        let record_pb = SubnetRecordPb::decode(record_bytes.as_slice())
            .map_err(|e| format!("Failed to decode SubnetRecord: {e}"))?;

        SubnetRecord::try_from(record_pb)
    }
}
