use ic_types::crypto::threshold_sig::IcRootOfTrust;
use mockall::mock;
use thiserror::Error;

#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[error("{0}")]
pub struct MockRootOfTrustProviderError(String);

mock! {
    pub RootOfTrustProvider {}

    impl ic_types::crypto::threshold_sig::RootOfTrustProvider for RootOfTrustProvider {
        type Error = MockRootOfTrustProviderError;

        fn root_of_trust(&self) -> Result<IcRootOfTrust, MockRootOfTrustProviderError>;
    }
}
