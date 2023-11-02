use candid::CandidType;
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::{proxy::ProxyDecodeError, registry::subnet::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

pub const DEFAULT_ECDSA_MAX_QUEUE_SIZE: u32 = 20;

/// List of features that can be enabled or disabled on the given subnet.
#[derive(CandidType, Clone, Copy, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct SubnetFeatures {
    /// This feature flag controls whether canister execution happens
    /// in sandboxed process or not. It is disabled by default.
    pub canister_sandboxing: bool,

    /// This feature flag controls whether canisters of this subnet are capable of
    /// performing http(s) requests to the web2.
    pub http_requests: bool,

    pub sev_status: Option<SevFeatureStatus>,
}

impl SubnetFeatures {
    pub fn sev_status(&self) -> SevFeatureStatus {
        self.sev_status.unwrap_or(SevFeatureStatus::Disabled)
    }
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            sev_status: features.sev_status.map(|s| match s {
                SevFeatureStatus::Disabled => 0,
                SevFeatureStatus::InsecureEnabled => 1,
                SevFeatureStatus::InsecureIntegrityEnabled => 2,
                SevFeatureStatus::SecureNoUpgradeEnabled => 3,
                SevFeatureStatus::SecureEnabled => 4,
            }),
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            canister_sandboxing: features.canister_sandboxing,
            http_requests: features.http_requests,
            sev_status: features.sev_status.map(|s| match s {
                1 => SevFeatureStatus::InsecureEnabled,
                2 => SevFeatureStatus::InsecureIntegrityEnabled,
                3 => SevFeatureStatus::SecureNoUpgradeEnabled,
                4 => SevFeatureStatus::SecureEnabled,
                _ => SevFeatureStatus::Disabled,
            }),
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

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub enum SevFeatureStatus {
    Disabled,
    InsecureEnabled,
    InsecureIntegrityEnabled,
    SecureNoUpgradeEnabled,
    SecureEnabled,
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
    #[test]
    fn test_sev_feature() {
        let features: &[(SevFeatureStatus, &str)] = &[
            (SevFeatureStatus::Disabled, "SEV_FEATURE_STATUS_UNSPECIFIED"),
            (
                SevFeatureStatus::InsecureEnabled,
                "SEV_FEATURE_STATUS_INSECURE_ENABLED",
            ),
            (
                SevFeatureStatus::InsecureIntegrityEnabled,
                "SEV_FEATURE_STATUS_INSECURE_INTEGRITY_ENABLED",
            ),
            (
                SevFeatureStatus::SecureNoUpgradeEnabled,
                "SEV_FEATURE_STATUS_SECURE_NO_UPGRADE_ENABLED",
            ),
            (
                SevFeatureStatus::SecureEnabled,
                "SEV_FEATURE_STATUS_SECURE_ENABLED",
            ),
        ];
        for feature in features {
            let status: pb::SevFeatureStatus = unsafe { ::std::mem::transmute(feature.0 as i32) };
            assert_eq!(pb::SevFeatureStatus::as_str_name(&status), feature.1);
        }
    }
}
