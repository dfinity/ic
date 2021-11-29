use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
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
