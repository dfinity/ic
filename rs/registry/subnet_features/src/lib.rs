use candid::CandidType;
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::{
    proxy::ProxyDecodeError,
    registry::{crypto::v1::MasterPublicKeyId as MasterPublicKeyIdPb, subnet::v1 as pb},
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

pub const DEFAULT_ECDSA_MAX_QUEUE_SIZE: u32 = 20;

/// List of features that can be enabled or disabled on the given subnet.
#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct SubnetFeatures {
    /// This feature flag controls whether canister execution happens
    /// in sandboxed process or not. It is disabled by default.
    pub canister_sandboxing: bool,

    /// This feature flag controls whether canisters of this subnet are capable of
    /// performing http(s) requests to the web2. It is enabled by default.
    /// TODO: The feature should be disabled only in special circumstances.
    /// Hence this field should be called 'disable_http_requests' and
    /// by default an empty value in the registry should suffice.
    #[serde(default = "default_http_requests")]
    pub http_requests: bool,

    /// This feature flag controls whether SEV is enabled on this subnet.
    pub sev_enabled: bool,
}

fn default_http_requests() -> bool {
    true
}

impl Default for SubnetFeatures {
    fn default() -> Self {
        Self {
            canister_sandboxing: bool::default(),
            http_requests: default_http_requests(),
            sev_enabled: bool::default(),
        }
    }
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            sev_enabled: features.sev_enabled.then_some(true),
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            sev_enabled: features.sev_enabled.unwrap_or_default(),
        }
    }
}

impl FromStr for SubnetFeatures {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        // Default value for bools is 'false'.
        let mut features = Self::default();

        if string.eq("None") {
            return Ok(features);
        }

        for feature in string.split(',') {
            match feature {
                "canister_sandboxing" => features.canister_sandboxing = true,
                "http_requests" => features.http_requests = true,
                "sev_enabled" => features.sev_enabled = true,
                _ => return Err(format!("Unknown feature {:?} in {:?}", feature, string)),
            }
        }

        Ok(features)
    }
}

#[derive(CandidType, Clone, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct EcdsaConfig {
    pub quadruples_to_create_in_advance: u32,
    pub key_ids: Vec<EcdsaKeyId>,
    pub max_queue_size: Option<u32>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

impl From<EcdsaConfig> for pb::EcdsaConfig {
    fn from(item: EcdsaConfig) -> Self {
        pb::EcdsaConfig {
            quadruples_to_create_in_advance: item.quadruples_to_create_in_advance,
            key_ids: item.key_ids.iter().map(|key| key.into()).collect(),
            max_queue_size: item.max_queue_size.unwrap_or(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: item.signature_request_timeout_ns,
            idkg_key_rotation_period_ms: item.idkg_key_rotation_period_ms,
        }
    }
}

impl TryFrom<pb::EcdsaConfig> for EcdsaConfig {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::EcdsaConfig) -> Result<Self, Self::Error> {
        let mut key_ids = vec![];
        for key in value.key_ids {
            key_ids.push(EcdsaKeyId::try_from(key)?);
        }
        Ok(EcdsaConfig {
            quadruples_to_create_in_advance: value.quadruples_to_create_in_advance,
            key_ids,
            max_queue_size: Some(value.max_queue_size),
            signature_request_timeout_ns: value.signature_request_timeout_ns,
            idkg_key_rotation_period_ms: value.idkg_key_rotation_period_ms,
        })
    }
}

#[derive(CandidType, Clone, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct KeyConfig {
    pub key_id: MasterPublicKeyId,
    pub pre_signatures_to_create_in_advance: u32,
    pub max_queue_size: Option<u32>,
}

impl From<KeyConfig> for pb::KeyConfig {
    fn from(src: KeyConfig) -> Self {
        let KeyConfig {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        let key_id = Some(MasterPublicKeyIdPb::from(key_id));

        let pre_signatures_to_create_in_advance = Some(pre_signatures_to_create_in_advance);

        Self {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        }
    }
}

#[derive(CandidType, Clone, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct ChainKeyConfig {
    pub key_configs: Vec<KeyConfig>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

impl From<ChainKeyConfig> for pb::ChainKeyConfig {
    fn from(src: ChainKeyConfig) -> Self {
        let ChainKeyConfig {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;

        let key_configs = key_configs.into_iter().map(pb::KeyConfig::from).collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        }
    }
}

/// This code is part of the data migration from `EcdsaConfig` to `ChainKeyConfig`.
///
/// Use this implementation to retrofit the values from an existing `EcdsaConfig` instance in places
/// where we now need a `ChainKeyConfig` instance.
///
/// TODO[NNS1-2986]: Remove this code.
impl From<EcdsaConfig> for ChainKeyConfig {
    fn from(src: EcdsaConfig) -> Self {
        let EcdsaConfig {
            key_ids,
            quadruples_to_create_in_advance,
            max_queue_size,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;

        let key_configs = key_ids
            .into_iter()
            .map(|key_id| KeyConfig {
                key_id: MasterPublicKeyId::Ecdsa(key_id),
                pre_signatures_to_create_in_advance: quadruples_to_create_in_advance,
                max_queue_size,
            })
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_none_is_accepted() {
        let result = SubnetFeatures::from_str("None").unwrap();
        assert_eq!(result, SubnetFeatures::default());
    }

    #[test]
    fn test_double_entries_are_handled() {
        let result = SubnetFeatures::from_str("canister_sandboxing,canister_sandboxing").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                canister_sandboxing: true,
                ..SubnetFeatures::default()
            }
        );
    }
}
