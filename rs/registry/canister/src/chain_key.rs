use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_management_canister_types::MasterPublicKeyId;
use ic_protobuf::registry::subnet::v1::{
    ChainKeyConfig as ChainKeyConfigPb, KeyConfig as KeyConfigPb,
};
use ic_registry_subnet_features::KeyConfig as KeyConfigInternal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub(crate) struct InitialChainKeyConfigInternal {
    pub key_configs: Vec<KeyConfigRequestInternal>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
}

impl InitialChainKeyConfigInternal {
    pub(crate) fn key_ids(&self) -> Vec<MasterPublicKeyId> {
        self.key_configs
            .iter()
            .map(|key_config_request| key_config_request.key_config.key_id.clone())
            .collect()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub(crate) struct KeyConfigRequestInternal {
    pub key_config: KeyConfigInternal,
    pub subnet_id: PrincipalId,
}

impl From<InitialChainKeyConfigInternal> for ChainKeyConfigPb {
    fn from(src: InitialChainKeyConfigInternal) -> Self {
        let InitialChainKeyConfigInternal {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        } = src;

        let key_configs = key_configs
            .into_iter()
            .map(|KeyConfigRequestInternal { key_config, .. }| KeyConfigPb::from(key_config))
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        }
    }
}
