#[allow(clippy::all)]
#[path = "../gen/registry/registry.subnet.v1.rs"]
pub mod v1;

use crate::registry::crypto::v1::{master_public_key_id, MasterPublicKeyId as MasterPublicKeyIdPb};
use crate::registry::subnet::v1::{
    ChainKeyConfig as ChainKeyConfigPb, EcdsaConfig as EcdsaConfigPb, KeyConfig as KeyConfigPb,
};

/// This code is part of the data migration from `EcdsaConfig` to `ChainKeyConfig`.
///
/// Use this implementation to retrofit the values from an existing `EcdsaConfig` instance in places
/// where we now need a `ChainKeyConfig` instance.
///
/// TODO[NNS1-2986]: Remove this code.
impl From<EcdsaConfigPb> for ChainKeyConfigPb {
    fn from(src: EcdsaConfigPb) -> Self {
        let EcdsaConfigPb {
            key_ids,
            quadruples_to_create_in_advance,
            max_queue_size,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;

        let pre_signatures_to_create_in_advance = Some(quadruples_to_create_in_advance);
        let max_queue_size = Some(max_queue_size);

        let key_configs = key_ids
            .into_iter()
            .map(|key_id| {
                let key_id = Some(master_public_key_id::KeyId::Ecdsa(key_id));
                let key_id = Some(MasterPublicKeyIdPb { key_id });
                KeyConfigPb {
                    key_id,
                    pre_signatures_to_create_in_advance,
                    max_queue_size,
                }
            })
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        }
    }
}
