use strum_macros::{EnumCount, EnumIter};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumCount, EnumIter)]
pub enum CertificationVersion {
    /// Added `flags` to `StreamHeader`. Defined `StreamHeaderFlagBits::ResponsesOnly` flag.
    V17 = 17,
    /// Added `deadline` fields to `Request` and `Response`.
    V18 = 18,
    /// Defined `reject_signals`, a struct containing 7 flavors of reject signals.
    /// Deprecated `reject_signals_deltas`.
    V19 = 19,
}

#[derive(Eq, PartialEq, Debug)]
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
        all_supported_versions()
            .find(|v| *v as u32 == n)
            .ok_or(UnsupportedCertificationVersion(n))
    }
}

/// The Canonical State certification version that should be used for newly
/// computed states.
pub const CURRENT_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V19;

/// Minimum supported certification version.
///
/// The replica will panic if requested to certify using a version lower than
/// this.
pub const MIN_SUPPORTED_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V17;

/// Maximum supported certification version.
///
/// The replica will panic if requested to certify using a version higher than
/// this.
pub const MAX_SUPPORTED_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V19;

/// Returns a list of all certification versions from `MIN_SUPPORTED_CERTIFICATION_VERSION`
/// up to `MAX_SUPPORTED_CERTIFICATION_VERSION`.
pub fn all_supported_versions() -> impl std::iter::Iterator<Item = CertificationVersion> {
    use strum::IntoEnumIterator;
    CertificationVersion::iter().filter(|v| {
        MIN_SUPPORTED_CERTIFICATION_VERSION <= *v && *v <= MAX_SUPPORTED_CERTIFICATION_VERSION
    })
}

#[test]
fn version_constants_consistent() {
    assert!(MIN_SUPPORTED_CERTIFICATION_VERSION <= CURRENT_CERTIFICATION_VERSION);
    assert!(CURRENT_CERTIFICATION_VERSION <= MAX_SUPPORTED_CERTIFICATION_VERSION);
}

#[test]
fn convert_from_u32_succeeds_for_all_supported_certification_versions() {
    use strum::IntoEnumIterator;
    assert!(all_supported_versions().all(|v| (v as u32).try_into() == Ok(v)));
    // Old unsupported version should fail.
    let v = CertificationVersion::iter().next().unwrap() as u32 - 1;
    assert_eq!(
        CertificationVersion::try_from(v),
        Err(UnsupportedCertificationVersion(v))
    );
    // Non-existent version should fail.
    let v = CertificationVersion::iter().last().unwrap() as u32 + 1;
    assert_eq!(
        CertificationVersion::try_from(v),
        Err(UnsupportedCertificationVersion(v))
    );
}
