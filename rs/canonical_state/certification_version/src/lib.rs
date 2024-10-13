use strum_macros::{EnumCount, EnumIter};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, EnumCount, EnumIter)]
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
    /// Dropped `SystemMetadata::id_counter`.
    V10 = 10,
    /// Producing `error_code` field in `request_status` subtree.
    V11 = 11,
    /// Added `/subnet/<own_subnet_id>/node` subtree, with node public keys.
    V12 = 12,
    /// Dropped `/canister/<canister_id>/controller`.
    V13 = 13,
    /// Define optional `Request::metadata` field.
    V14 = 14,
    /// Added subnet metrics in `subnet` subtree.
    V15 = 15,
    /// Added `/api_boundary_nodes` subtree with domain, ipv4_address and ipv6_address for each API boundary node.
    V16 = 16,
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
        use strum::IntoEnumIterator;
        CertificationVersion::iter()
            .nth(n as usize)
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
pub const MIN_SUPPORTED_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V15;

/// Maximum supported certification version.
///
/// The replica will panic if requested to certify using a version higher than
/// this.
pub const MAX_SUPPORTED_CERTIFICATION_VERSION: CertificationVersion = CertificationVersion::V19;

/// Returns a list of all certification versions up to [MAX_SUPPORTED_CERTIFICATION_VERSION].
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
