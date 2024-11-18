use ic_types::crypto::threshold_sig::IcRootOfTrust;
use mockall::mock;
use thiserror::Error;

#[derive(Clone, Eq, PartialEq, Debug, Error)]
#[error("{0}")]
pub struct MockRootOfTrustProviderError(String);

impl MockRootOfTrustProviderError {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

mock! {
    pub RootOfTrustProvider {}

    impl ic_types::crypto::threshold_sig::RootOfTrustProvider for RootOfTrustProvider {
        type Error = MockRootOfTrustProviderError;

        fn root_of_trust(&self) -> Result<IcRootOfTrust, MockRootOfTrustProviderError>;
    }
}
