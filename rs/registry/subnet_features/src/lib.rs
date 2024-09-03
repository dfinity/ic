use candid::CandidType;
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::{crypto::v1 as crypto_pb, subnet::v1 as pb},
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

pub const DEFAULT_ECDSA_MAX_QUEUE_SIZE: u32 = 20;

/// List of features that can be enabled or disabled on the given subnet.
#[derive(Copy, Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
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

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
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

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct KeyConfig {
    pub key_id: MasterPublicKeyId,
    pub pre_signatures_to_create_in_advance: u32,
    pub max_queue_size: u32,
}

impl From<KeyConfig> for pb::KeyConfig {
    fn from(src: KeyConfig) -> Self {
        let KeyConfig {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        let key_id = Some(crypto_pb::MasterPublicKeyId::from(&key_id));

        let pre_signatures_to_create_in_advance = Some(pre_signatures_to_create_in_advance);

        Self {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size: Some(max_queue_size),
        }
    }
}

impl TryFrom<pb::KeyConfig> for KeyConfig {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::KeyConfig) -> Result<Self, Self::Error> {
        Ok(KeyConfig {
            pre_signatures_to_create_in_advance: try_from_option_field(
                value.pre_signatures_to_create_in_advance,
                "KeyConfig::pre_signatures_to_create_in_advance",
            )?,
            key_id: try_from_option_field(value.key_id, "KeyConfig::key_id")?,
            max_queue_size: try_from_option_field(
                value.max_queue_size,
                "KeyConfig::max_queue_size",
            )?,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct ChainKeyConfig {
    pub key_configs: Vec<KeyConfig>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

impl ChainKeyConfig {
    pub fn key_ids(&self) -> Vec<MasterPublicKeyId> {
        self.key_configs
            .iter()
            .map(|key_config| key_config.key_id.clone())
            .collect()
    }
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

impl TryFrom<pb::ChainKeyConfig> for ChainKeyConfig {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::ChainKeyConfig) -> Result<Self, Self::Error> {
        let mut key_configs = vec![];
        for key_config in value.key_configs {
            key_configs.push(KeyConfig::try_from(key_config)?);
        }
        Ok(ChainKeyConfig {
            key_configs,
            signature_request_timeout_ns: value.signature_request_timeout_ns,
            idkg_key_rotation_period_ms: value.idkg_key_rotation_period_ms,
        })
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
                max_queue_size: max_queue_size.unwrap_or(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
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
    use ic_management_canister_types::EcdsaCurve;

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

    #[test]
    fn test_chain_key_config_from_ecdsa_config() {
        // Run code under test.
        let chain_key_config = ChainKeyConfig::from(EcdsaConfig {
            quadruples_to_create_in_advance: 77,
            key_ids: vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test_curve".to_string(),
            }],
            max_queue_size: Some(30),
            signature_request_timeout_ns: Some(123_456),
            idkg_key_rotation_period_ms: Some(321_654),
        });
        // Assert expected result value.
        assert_eq!(
            chain_key_config,
            ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "test_curve".to_string(),
                    }),
                    pre_signatures_to_create_in_advance: 77,
                    max_queue_size: 30,
                }],
                signature_request_timeout_ns: Some(123_456),
                idkg_key_rotation_period_ms: Some(321_654),
            }
        );
    }

    #[test]
    fn test_chain_key_config_pb_from_ecdsa_config_pb() {
        // Run code under test.
        let chain_key_config_pb = pb::ChainKeyConfig::from(pb::EcdsaConfig {
            quadruples_to_create_in_advance: 77,
            key_ids: vec![crypto_pb::EcdsaKeyId {
                curve: 1,
                name: "test_curve".to_string(),
            }],
            max_queue_size: 30,
            signature_request_timeout_ns: Some(123_456),
            idkg_key_rotation_period_ms: Some(321_654),
        });
        // Assert expected result value.
        assert_eq!(
            chain_key_config_pb,
            pb::ChainKeyConfig {
                key_configs: vec![pb::KeyConfig {
                    key_id: Some(crypto_pb::MasterPublicKeyId {
                        key_id: Some(crypto_pb::master_public_key_id::KeyId::Ecdsa(
                            crypto_pb::EcdsaKeyId {
                                curve: 1,
                                name: "test_curve".to_string(),
                            }
                        )),
                    }),
                    pre_signatures_to_create_in_advance: Some(77),
                    max_queue_size: Some(30),
                }],
                signature_request_timeout_ns: Some(123_456),
                idkg_key_rotation_period_ms: Some(321_654),
            }
        );
    }

    #[test]
    fn test_chain_key_config_round_trip() {
        // Run code under test.
        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test_curve".to_string(),
                }),
                pre_signatures_to_create_in_advance: 77,
                max_queue_size: 30,
            }],
            signature_request_timeout_ns: Some(123_456),
            idkg_key_rotation_period_ms: Some(321_654),
        };

        let chain_key_config_pb = pb::ChainKeyConfig::from(chain_key_config.clone());

        // Assert expected result value.
        let expected_chain_key_config_pb = pb::ChainKeyConfig {
            key_configs: vec![pb::KeyConfig {
                key_id: Some(crypto_pb::MasterPublicKeyId {
                    key_id: Some(crypto_pb::master_public_key_id::KeyId::Ecdsa(
                        crypto_pb::EcdsaKeyId {
                            curve: 1,
                            name: "test_curve".to_string(),
                        },
                    )),
                }),
                pre_signatures_to_create_in_advance: Some(77),
                max_queue_size: Some(30),
            }],
            signature_request_timeout_ns: Some(123_456),
            idkg_key_rotation_period_ms: Some(321_654),
        };

        assert_eq!(chain_key_config_pb, expected_chain_key_config_pb,);

        let chain_key_config_after_deser =
            ChainKeyConfig::try_from(chain_key_config_pb).expect("Deserialization should succeed.");

        assert_eq!(chain_key_config, chain_key_config_after_deser,);
    }

    #[test]
    fn test_chain_key_config_pb_from_ecdsa_config() {
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 77,
            key_ids: vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test_curve".to_string(),
            }],
            max_queue_size: Some(30),
            signature_request_timeout_ns: Some(123_456),
            idkg_key_rotation_period_ms: Some(321_654),
        };

        let chain_key_config = ChainKeyConfig::from(ecdsa_config.clone());
        let chain_key_config_pb_a = pb::ChainKeyConfig::from(chain_key_config);

        let ecdsa_config_pb = pb::EcdsaConfig::from(ecdsa_config);
        let chain_key_config_pb_b = pb::ChainKeyConfig::from(ecdsa_config_pb);

        assert_eq!(chain_key_config_pb_a, chain_key_config_pb_b);
    }
}
