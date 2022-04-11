use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumIter)]
pub enum CertificationVersion {
    /// Initial version.
    V0 = 0,
    /// Added canister module hash and controller.
    V1 = 1,
    /// Added support for multiple canister controllers.
    V2 = 2,
    /// Added subnet to canister ID ranges routing tables.
    V3 = 3,
    /// Added optional `Request::cycles_payment` and `Response::cycles_refund`
    /// fields that are not yet populated.
    V4 = 4,
    /// Added support for canister metadata custom sections.
    V5 = 5,
    /// Encoding of canister metadata custom sections.
    V6 = 6,
    /// Support for decoding of `StreamHeader::reject_signals`.
    /// Support for `done` ingress history status.
    V7 = 7,
    /// Encoding of `StreamHeader::reject_signals`.
    /// Producing `done` ingress history statuses.
    V8 = 8,
    /// Producing non-empty `StreamHeader::reject_signals`.
    V9 = 9,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnsupportedCertificationVersion(u32);

impl std::fmt::Display for UnsupportedCertificationVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use strum::IntoEnumIterator;
        write!(
            f,
            "Certification version {} is not defined, known versions: {:?}",
            self.0,
            CertificationVersion::iter()
                .map(|v| v as u32)
                .collect::<Vec<_>>()
        )
    }
}

impl std::convert::TryFrom<u32> for CertificationVersion {
    type Error = UnsupportedCertificationVersion;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;
        CertificationVersion::iter()
            .nth(n as usize)
            .ok_or(UnsupportedCertificationVersion(n))
    }
}

/// The Canonical State certification version that should be used for newly
/// computed states.
pub const CURRENT_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V8;

/// Maximum supported certification version.
///
/// The replica will panic if requested to certify using a version higher than
/// this.
pub const MAX_SUPPORTED_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V9;

/// Returns a list of all certification versions up to [MAX_SUPPORTED_CERTIFICATION_VERSION].
pub fn all_supported_versions() -> impl std::iter::Iterator<Item = CertificationVersion> {
    use strum::IntoEnumIterator;
    CertificationVersion::iter().take_while(|v| *v <= MAX_SUPPORTED_CERTIFICATION_VERSION)
}

#[test]
fn supported_version_ge_current() {
    assert!(CURRENT_CERTIFICATION_VERSION <= MAX_SUPPORTED_CERTIFICATION_VERSION);
}
