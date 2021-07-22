use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_protobuf::registry::conversion_rate::v1::IcpXdrConversionRateRecord;
use ic_registry_keys::make_icp_xdr_conversion_rate_record_key;
use ic_registry_transport::upsert;

impl Registry {
    pub fn do_update_icp_xdr_conversion_rate(
        &mut self,
        payload: UpdateIcpXdrConversionRatePayload,
    ) {
        println!(
            "{}do_update_icp_xdr_conversion_rate: {:?}",
            LOG_PREFIX, payload
        );

        // If there is no ICP/XDR conversion rate, we have to Insert new one
        let mutations = vec![upsert(
            make_icp_xdr_conversion_rate_record_key()
                .as_bytes()
                .to_vec(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&payload.into()),
        )];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to update the ICP/XDR conversion rate.
///
/// See /rs/protobuf/def/registry/conversion_rate/v1/conversion_rate.proto for
/// the explanation of the fields for the IcpXdrConversionRateRecord.
/// The fields will be used by the subnet canister to create an
/// IcpXdrConversionRateRecord.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateIcpXdrConversionRatePayload {
    pub data_source: String,
    pub timestamp_seconds: u64,
    pub xdr_permyriad_per_icp: u64,
}

impl From<UpdateIcpXdrConversionRatePayload> for IcpXdrConversionRateRecord {
    fn from(val: UpdateIcpXdrConversionRatePayload) -> Self {
        IcpXdrConversionRateRecord {
            timestamp_seconds: val.timestamp_seconds,
            xdr_permyriad_per_icp: val.xdr_permyriad_per_icp,
        }
    }
}
