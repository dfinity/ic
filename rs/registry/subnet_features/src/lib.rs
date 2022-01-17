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
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
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
                _ => return Err(format!("Unknown feature {:?} in {:?}", feature, string)),
            }
        }

        Ok(features)
    }
}

#[cfg(test)]
mod tests {
    use crate::SubnetFeatures;
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
        let result =
            SubnetFeatures::from_str("ecdsa_signatures,canister_sandboxing,http_requests").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: true,
                canister_sandboxing: true,
                http_requests: true,
            }
        );
    }
}
