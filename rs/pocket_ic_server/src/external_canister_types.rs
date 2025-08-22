use candid::CandidType;

/* Internet Identity */

pub type AnchorNumber = u64;

#[derive(CandidType)]
pub struct ArchiveConfig {
    pub module_hash: [u8; 32],
    pub entries_buffer_limit: u64,
    pub polling_interval_ns: u64,
    pub entries_fetch_limit: u16,
}

#[derive(CandidType)]
pub struct RateLimitConfig {
    pub time_per_token_ns: u64,
    pub max_tokens: u64,
}

#[derive(CandidType)]
pub enum StaticCaptchaTrigger {
    #[allow(dead_code)]
    CaptchaEnabled,
    CaptchaDisabled,
}

#[derive(CandidType)]
pub enum CaptchaTrigger {
    #[allow(dead_code)]
    Dynamic {
        threshold_pct: u16,
        current_rate_sampling_interval_s: u64,
        reference_rate_sampling_interval_s: u64,
    },
    Static(StaticCaptchaTrigger),
}

#[derive(CandidType)]
pub struct CaptchaConfig {
    pub max_unsolved_captchas: u64,
    pub captcha_trigger: CaptchaTrigger,
}

#[derive(CandidType)]
pub struct OpenIdConfig {
    pub client_id: String,
}

#[allow(dead_code)]
#[derive(CandidType)]
pub enum AnalyticsConfig {
    Plausible {
        domain: Option<String>,
        hash_mode: Option<bool>,
        track_localhost: Option<bool>,
        api_host: Option<String>,
    },
}

#[derive(CandidType)]
pub struct DummyAuthConfig {
    pub prompt_for_index: bool,
}

#[derive(CandidType)]
pub struct InternetIdentityInit {
    pub assigned_user_number_range: Option<(AnchorNumber, AnchorNumber)>,
    pub archive_config: Option<ArchiveConfig>,
    pub canister_creation_cycles_cost: Option<u64>,
    pub register_rate_limit: Option<RateLimitConfig>,
    pub captcha_config: Option<CaptchaConfig>,
    pub related_origins: Option<Vec<String>>,
    pub new_flow_origins: Option<Vec<String>>,
    pub openid_google: Option<Option<OpenIdConfig>>,
    pub analytics_config: Option<Option<AnalyticsConfig>>,
    pub fetch_root_key: Option<bool>,
    pub enable_dapps_explorer: Option<bool>,
    pub is_production: Option<bool>,
    pub dummy_auth: Option<Option<DummyAuthConfig>>,
    pub feature_flag_continue_from_another_device: Option<bool>,
}

#[cfg(test)]
mod tests {
    use crate::external_canister_types::InternetIdentityInit;
    use candid::types::subtype::equal;
    use candid::CandidType;
    use candid_parser::utils::{instantiate_candid, CandidSource};
    use flate2::read::GzDecoder;
    use std::io::Read;
    use walrus::{IdsToIndices, Module};

    fn check_init_arg<T: CandidType>(gzipped_canister_wasm: &[u8]) {
        let mut decoder = GzDecoder::new(gzipped_canister_wasm);
        let mut canister_wasm = Vec::new();
        decoder.read_to_end(&mut canister_wasm).unwrap();
        let module = Module::from_buffer(&canister_wasm).unwrap();
        let canister_did = module
            .customs
            .iter()
            .find(|(_, c)| c.name() == "icp:public candid:service")
            .unwrap()
            .1
            .data(&IdsToIndices::default());
        let (init_args, (env, _)) = instantiate_candid(CandidSource::Text(
            core::str::from_utf8(&canister_did).unwrap(),
        ))
        .unwrap();

        assert_eq!(init_args.len(), 1);
        let mut gamma = std::collections::HashSet::new();
        equal(&mut gamma, &env, &init_args[0], &T::ty()).unwrap();
    }

    #[test]
    fn internet_identity_candid_equality() {
        const INTERNET_IDENTITY_TEST_CANISTER_WASM: &[u8] =
            include_bytes!(env!("INTERNET_IDENTITY_TEST_CANISTER_WASM_PATH"));

        check_init_arg::<Option<InternetIdentityInit>>(INTERNET_IDENTITY_TEST_CANISTER_WASM);
    }
}
