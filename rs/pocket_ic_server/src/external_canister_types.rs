use candid::{CandidType, Principal};
use icrc_ledger_types::icrc1::account::Account;

/* NNS dapp */

#[derive(CandidType)]
pub struct NnsDappCanisterArguments {
    pub args: Vec<(String, String)>,
}

/* SNS aggregator */

#[derive(CandidType)]
pub struct SnsAggregatorConfig {
    pub update_interval_ms: u64,
    pub fast_interval_ms: u64,
}

/* Cycles ledger */

#[derive(CandidType)]
pub struct CyclesLedgerConfig {
    pub max_blocks_per_request: u64,
    pub index_id: Option<Principal>,
    pub initial_balances: Option<Vec<(Account, u128)>>,
}

#[derive(CandidType)]
pub enum ChangeIndexId {
    Unset,
    SetTo(Principal),
}

#[derive(CandidType)]
pub struct CyclesLedgerUpgradeArgs {
    pub max_blocks_per_request: Option<u64>,
    pub change_index_id: Option<ChangeIndexId>,
}

#[derive(CandidType)]
pub enum CyclesLedgerArgs {
    Init(CyclesLedgerConfig),
    Upgrade(Option<CyclesLedgerUpgradeArgs>),
}

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
    pub name: String,
    pub logo: String,
    pub issuer: String,
    pub client_id: String,
    pub jwks_uri: String,
    pub auth_uri: String,
    pub auth_scope: Vec<String>,
    pub fedcm_uri: Option<String>,
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
    pub openid_configs: Option<Vec<OpenIdConfig>>,
    pub analytics_config: Option<Option<AnalyticsConfig>>,
    pub fetch_root_key: Option<bool>,
    pub enable_dapps_explorer: Option<bool>,
    pub is_production: Option<bool>,
    pub dummy_auth: Option<Option<DummyAuthConfig>>,
}
