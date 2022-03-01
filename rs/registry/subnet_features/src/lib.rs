use candid::CandidType;
use ic_protobuf::registry::subnet::v1 as pb;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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

    /// Whether or not this subnet supports the Bitcoin testnet.
    pub bitcoin_testnet_feature: Option<BitcoinFeature>,
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            bitcoin_testnet_feature: features.bitcoin_testnet_feature.map(|f| f.into()),
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            bitcoin_testnet_feature: features.bitcoin_testnet_feature.map(BitcoinFeature::from),
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
                    if features.bitcoin_testnet_feature.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from(
                            "Cannot set bitcoin_testnet feature more than once",
                        ));
                    }

                    features.bitcoin_testnet_feature = Some(BitcoinFeature::Enabled);
                }
                "bitcoin_testnet_paused" => {
                    if features.bitcoin_testnet_feature.is_some() {
                        // Feature was already set. Return an error.
                        return Err(String::from(
                            "Cannot set bitcoin_testnet feature more than once",
                        ));
                    }

                    features.bitcoin_testnet_feature = Some(BitcoinFeature::Paused);
                }
                _ => return Err(format!("Unknown feature {:?} in {:?}", feature, string)),
            }
        }

        Ok(features)
    }
}

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub enum BitcoinFeature {
    Disabled,
    Paused,
    Enabled,
}

impl From<BitcoinFeature> for i32 {
    fn from(bitcoin_feature: BitcoinFeature) -> i32 {
        match bitcoin_feature {
            BitcoinFeature::Disabled => 0,
            BitcoinFeature::Paused => 1,
            BitcoinFeature::Enabled => 2,
        }
    }
}

impl From<i32> for BitcoinFeature {
    fn from(input: i32) -> Self {
        match input {
            0 => Self::Disabled,
            1 => Self::Paused,
            2 => Self::Enabled,
            // An unknown enumeration value. Consider the feature disabled.
            // An alternative would be to return an error, but this would result in
            // unnecessary complications to the callers.
            _ => Self::Disabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{BitcoinFeature, SubnetFeatures};
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
                bitcoin_testnet_feature: Some(BitcoinFeature::Enabled),
            }
        );
    }

    #[test]
    fn test_bitcoin_testnet_paused() {
        let result =
            SubnetFeatures::from_str("canister_sandboxing,http_requests,bitcoin_testnet_paused")
                .unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: false,
                canister_sandboxing: true,
                http_requests: true,
                bitcoin_testnet_feature: Some(BitcoinFeature::Paused),
            }
        );
    }

    #[test]
    fn test_set_bitcoin_testnet_multiple_times_returns_error() {
        assert!(SubnetFeatures::from_str(
            "canister_sandboxing,http_requests,bitcoin_testnet_paused,bitcoin_testnet",
        )
        .is_err());
    }
}
