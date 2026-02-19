use super::{OverrideProvider, StorableLogFilter};
use canlog::{LogFilter, RegexString, RegexSubstitution};
use ic_stable_structures::Storable;
use proptest::{
    option,
    prelude::{prop_oneof, proptest, Just, Strategy},
};
use std::fmt::Debug;

mod encoding_decoding {
    use super::*;

    proptest! {
        #[test]
        fn should_encode_decode_log_filter(value in arb_log_filter()) {
            test_encoding_decoding_roundtrip(&value);
        }

        #[test]
        fn should_encode_decode_override_provider(value in arb_override_provider()) {
            test_encoding_decoding_roundtrip(&value);
        }
    }

    fn test_encoding_decoding_roundtrip<T: Storable + PartialEq + Debug>(value: &T) {
        let bytes = value.to_bytes();
        let decoded_value = T::from_bytes(bytes);
        assert_eq!(value, &decoded_value);
    }
}

mod decode_legacy_log_filter {
    use super::arb_log_filter;
    use crate::types::StorableLogFilter;
    use ic_stable_structures::{storable::Bound, Storable};
    use proptest::proptest;
    use serde::{Deserialize, Serialize};
    use std::{borrow::Cow, fmt::Debug};

    proptest! {
        #[test]
        fn should_decode_legacy_log_filter(log_filter in arb_log_filter()) {
            let legacy_filter = LogFilter::from(log_filter.clone());
            let legacy_bytes = legacy_filter.to_bytes();
            let log_filter_from_legacy = StorableLogFilter::from_bytes(legacy_bytes);
            assert_eq!(log_filter_from_legacy, log_filter);
        }
    }

    // This is the legacy implementation of the log filter. For backwards-compatibility, instances
    // of this type stored in stable memory should be deserialized correctly.
    #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub enum LogFilter {
        #[default]
        ShowAll,
        HideAll,
        ShowPattern(RegexString),
        HidePattern(RegexString),
    }

    impl From<StorableLogFilter> for LogFilter {
        fn from(value: StorableLogFilter) -> Self {
            match value.0 {
                canlog::LogFilter::ShowAll => Self::ShowAll,
                canlog::LogFilter::HideAll => Self::HideAll,
                canlog::LogFilter::ShowPattern(canlog::RegexString(value)) => {
                    Self::ShowPattern(RegexString(value))
                }
                canlog::LogFilter::HidePattern(canlog::RegexString(value)) => {
                    Self::HidePattern(RegexString(value))
                }
            }
        }
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub struct RegexString(String);

    impl Storable for LogFilter {
        fn to_bytes(&self) -> Cow<'_, [u8]> {
            serde_json::to_vec(self)
                .expect("Error while serializing `LogFilter`")
                .into()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            serde_json::from_slice(&bytes).expect("Error while deserializing `LogFilter`")
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: 1000,
            is_fixed_size: true,
        };
    }
}

fn arb_regex_string() -> impl Strategy<Value = RegexString> {
    ".*".prop_map(RegexString)
}

fn arb_regex_substitution() -> impl Strategy<Value = RegexSubstitution> {
    (arb_regex_string(), ".*").prop_map(|(pattern, replacement)| RegexSubstitution {
        pattern,
        replacement,
    })
}

fn arb_log_filter() -> impl Strategy<Value = StorableLogFilter> {
    prop_oneof![
        Just(LogFilter::ShowAll),
        Just(LogFilter::HideAll),
        arb_regex_string().prop_map(LogFilter::ShowPattern),
        arb_regex_string().prop_map(LogFilter::HidePattern),
    ]
    .prop_map(StorableLogFilter)
}

fn arb_override_provider() -> impl Strategy<Value = OverrideProvider> {
    option::of(arb_regex_substitution()).prop_map(|override_url| OverrideProvider { override_url })
}

mod override_provider {
    use crate::memory::insert_api_key;
    use crate::providers::PROVIDERS;
    use crate::types::{ApiKey, OverrideProvider, RegexSubstitution};
    use evm_rpc_types::RpcApi;
    use ic_management_canister_types::HttpHeader;

    #[test]
    fn should_override_provider_with_localhost() {
        setup_api_keys();
        let override_provider = override_to_localhost();
        for provider in PROVIDERS {
            let overriden_provider = override_provider.apply(provider.api());
            assert_eq!(
                overriden_provider,
                Ok(RpcApi {
                    url: "http://localhost:8545".to_string(),
                    headers: None
                })
            )
        }
    }

    #[test]
    fn should_be_noop_when_empty() {
        setup_api_keys();
        let no_override = OverrideProvider::default();
        for provider in PROVIDERS {
            let initial_api = provider.api();
            let overriden_api = no_override.apply(initial_api.clone());
            assert_eq!(Ok(initial_api), overriden_api);
        }
    }

    #[test]
    fn should_use_replacement_pattern() {
        setup_api_keys();
        let identity_override = OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: "(?<url>.*)".into(),
                replacement: "$url".to_string(),
            }),
        };
        for provider in PROVIDERS {
            let initial_api = provider.api();
            let overriden_provider = identity_override.apply(initial_api.clone()).unwrap();
            assert_eq!(overriden_provider.headers, None);
            assert_eq!(overriden_provider.url, initial_api.url)
        }
    }

    #[test]
    fn should_override_headers() {
        setup_api_keys();
        let identity_override = OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: "(.*)".into(),
                replacement: "$1".to_string(),
            }),
        };
        for provider in PROVIDERS {
            let provider_with_headers = RpcApi {
                headers: Some(vec![HttpHeader {
                    name: "key".to_string(),
                    value: "123".to_string(),
                }]),
                ..provider.api()
            };
            let overriden_provider = identity_override.apply(provider_with_headers.clone());
            assert_eq!(
                overriden_provider,
                Ok(RpcApi {
                    url: provider_with_headers.url,
                    headers: None
                })
            )
        }
    }

    fn setup_api_keys() {
        for provider in PROVIDERS {
            insert_api_key(
                provider.provider_id,
                ApiKey::try_from("unit-test-key".to_string()).unwrap(),
            )
        }
    }

    fn override_to_localhost() -> OverrideProvider {
        OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: "^https://.*".into(),
                replacement: "http://localhost:8545".to_string(),
            }),
        }
    }
}
