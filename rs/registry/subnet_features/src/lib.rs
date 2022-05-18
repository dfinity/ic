use candid::CandidType;
use ic_ic00_types::{BitcoinNetwork, EcdsaKeyId};
use ic_protobuf::{proxy::ProxyDecodeError, registry::subnet::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

/// List of features that can be enabled or disabled on the given subnet.
#[derive(CandidType, Clone, Copy, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct SubnetFeatures {
    /// This feature flag controls whether canisters of this subnet are capable of
    /// issuing threshold ecdsa signatures.
    pub ecdsa_signatures: bool,

    /// This feature flag controls whether canister execution happens
    /// in sandboxed process or not. It is disabled by default.
    pub canister_sandboxing: bool,

    /// This feature flag controls whether canisters of this subnet are capable of
    /// performing http(s) requests to the web2.
    pub http_requests: bool,

    /// Determines whether or not the bitcoin feature is enabled on the subnet.
    pub bitcoin: Option<BitcoinFeature>,
}

impl SubnetFeatures {
    pub fn bitcoin(&self) -> BitcoinFeature {
        self.bitcoin.unwrap_or(BitcoinFeature {
            network: BitcoinNetwork::Mainnet,
            status: BitcoinFeatureStatus::Disabled,
        })
    }
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            bitcoin_testnet_feature: None,
            bitcoin: features
                .bitcoin
                .map(|bitcoin_feature| pb::BitcoinFeatureInfo {
                    network: match bitcoin_feature.network {
                        BitcoinNetwork::Testnet => 1,
                        BitcoinNetwork::Mainnet => 2,
                    },
                    status: bitcoin_feature.status.into(),
                }),
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            bitcoin: match features.bitcoin {
                Some(bitcoin) => Some(BitcoinFeature {
                    network: match bitcoin.network {
                        1 => BitcoinNetwork::Testnet,
                        2 => BitcoinNetwork::Mainnet,
                        // If an invalid value is provided, assume mainnet.
                        _ => BitcoinNetwork::Mainnet,
                    },
                    status: bitcoin.status.into(),
                }),
                None => {
                    // For backward-compatibility, check if the legacy `bitcoin_testnet_feature`
                    // field is populated and load that instead.
                    // TODO(EXC-1114): Remove this logic once this commit is released.
                    features
                        .bitcoin_testnet_feature
                        .map(|legacy_bitcoin_feature| BitcoinFeature {
                            network: BitcoinNetwork::Testnet,
                            status: BitcoinFeatureStatus::from(legacy_bitcoin_feature),
                        })
                }
            },
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
                "ecdsa_signatures" => features.ecdsa_signatures = true,
                "canister_sandboxing" => features.canister_sandboxing = true,
                "http_requests" => features.http_requests = true,
                "bitcoin_testnet" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Testnet,
                        status: BitcoinFeatureStatus::Enabled,
                    });
                }
                "bitcoin_testnet_syncing" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Testnet,
                        status: BitcoinFeatureStatus::Syncing,
                    });
                }
                "bitcoin_testnet_paused" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Testnet,
                        status: BitcoinFeatureStatus::Paused,
                    });
                }
                "bitcoin_mainnet" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Mainnet,
                        status: BitcoinFeatureStatus::Enabled,
                    });
                }
                "bitcoin_mainnet_syncing" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Mainnet,
                        status: BitcoinFeatureStatus::Syncing,
                    });
                }
                "bitcoin_mainnet_paused" => {
                    if features.bitcoin.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from("Cannot set bitcoin feature more than once"));
                    }

                    features.bitcoin = Some(BitcoinFeature {
                        network: BitcoinNetwork::Mainnet,
                        status: BitcoinFeatureStatus::Paused,
                    });
                }
                _ => return Err(format!("Unknown feature {:?} in {:?}", feature, string)),
            }
        }

        Ok(features)
    }
}

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct BitcoinFeature {
    pub network: BitcoinNetwork,
    pub status: BitcoinFeatureStatus,
}

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub enum BitcoinFeatureStatus {
    Disabled,
    Paused,
    Syncing,
    Enabled,
}

impl From<BitcoinFeatureStatus> for i32 {
    fn from(status: BitcoinFeatureStatus) -> i32 {
        match status {
            BitcoinFeatureStatus::Disabled => 0,
            BitcoinFeatureStatus::Paused => 1,
            BitcoinFeatureStatus::Enabled => 2,
            BitcoinFeatureStatus::Syncing => 3,
        }
    }
}

impl From<i32> for BitcoinFeatureStatus {
    fn from(input: i32) -> Self {
        match input {
            0 => Self::Disabled,
            1 => Self::Paused,
            2 => Self::Enabled,
            3 => Self::Syncing,
            // An unknown enumeration value. Consider the feature disabled.
            // An alternative would be to return an error, but this would result in
            // unnecessary complications to the callers.
            _ => Self::Disabled,
        }
    }
}

#[derive(CandidType, Clone, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct EcdsaConfig {
    pub quadruples_to_create_in_advance: u32,
    pub key_ids: Vec<EcdsaKeyId>,
}

impl From<EcdsaConfig> for pb::EcdsaConfig {
    fn from(item: EcdsaConfig) -> Self {
        pb::EcdsaConfig {
            quadruples_to_create_in_advance: item.quadruples_to_create_in_advance,
            key_ids: item.key_ids.iter().map(|key| key.into()).collect(),
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
        })
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
        let result = SubnetFeatures::from_str("ecdsa_signatures,ecdsa_signatures").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: true,
                ..SubnetFeatures::default()
            }
        );
    }

    #[test]
    fn test_all_can_be_set_true() {
        let result = SubnetFeatures::from_str(
            "ecdsa_signatures,canister_sandboxing,http_requests,bitcoin_testnet",
        )
        .unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: true,
                canister_sandboxing: true,
                http_requests: true,
                bitcoin: Some(BitcoinFeature {
                    network: BitcoinNetwork::Testnet,
                    status: BitcoinFeatureStatus::Enabled
                })
            }
        );
    }

    #[test]
    fn test_bitcoin_mainnet_paused() {
        let result =
            SubnetFeatures::from_str("canister_sandboxing,http_requests,bitcoin_mainnet_paused")
                .unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: false,
                canister_sandboxing: true,
                http_requests: true,
                bitcoin: Some(BitcoinFeature {
                    network: BitcoinNetwork::Mainnet,
                    status: BitcoinFeatureStatus::Paused
                })
            }
        );
    }

    #[test]
    fn test_bitcoin_mainnet() {
        let result =
            SubnetFeatures::from_str("canister_sandboxing,http_requests,bitcoin_mainnet").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: false,
                canister_sandboxing: true,
                http_requests: true,
                bitcoin: Some(BitcoinFeature {
                    network: BitcoinNetwork::Mainnet,
                    status: BitcoinFeatureStatus::Enabled
                })
            }
        );
    }

    #[test]
    fn test_set_bitcoin_multiple_times_returns_error() {
        assert!(SubnetFeatures::from_str(
            "canister_sandboxing,http_requests,bitcoin_testnet_paused,bitcoin_testnet",
        )
        .is_err());
    }

    #[test]
    fn test_bitcoin_to_from_proto() {
        for feature in [
            "bitcoin_mainnet",
            "bitcoin_mainnet_paused",
            "bitcoin_testnet",
            "bitcoin_testnet_paused",
        ] {
            let subnet_feature = SubnetFeatures::from_str(feature).unwrap();
            assert_eq!(
                subnet_feature,
                SubnetFeatures::from(pb::SubnetFeatures::from(subnet_feature))
            );
        }
    }
}
