use ic_base_types::PrincipalId;
use ic_canonical_state::{
    encoding::{
        old_types::{
            RequestOrResponseV13, RequestOrResponseV17, RequestOrResponseV3, StreamHeaderV16,
            StreamHeaderV18, StreamHeaderV6, SystemMetadataV9,
        },
        types::{
            RequestOrResponse as RequestOrResponseV18, StreamHeader as StreamHeaderV19,
            SubnetMetrics as SubnetMetricsV15, SystemMetadata as SystemMetadataV10,
        },
        CborProxyDecoder, CborProxyEncoder,
    },
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION,
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_replicated_state::{metadata_state::SubnetMetrics, SystemMetadata};
use ic_test_utilities_state::{arb_stream_header, arb_subnet_metrics};
use ic_test_utilities_types::arbitrary;
use ic_types::{
    crypto::CryptoHash,
    messages::RequestOrResponse,
    xnet::{RejectReason, StreamHeader},
    CryptoHashOfPartialState,
};
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::ops::RangeInclusive;
use strum::IntoEnumIterator;

/// A named combination of canonical type; and the certification version range
/// that it may be applied within; for encoding and decoding values of type `T`.
///
/// E.g. `StreamHeaderV6` may be used for encoding and decoding `StreamHeader`
/// values for any certification version in range `0..=6`.
///
/// Per https://stackoverflow.com/questions/67342223/one-type-function-pointer-is-more-general-than-the-other
/// the Rust compiler is unable to "automatically convert generic functions
/// which include a type bounded by a lifetime into a function pointer that
/// is fully generic over that lifetime".
///
/// The recommended workaround is to wrap the generic call within a
/// non-generic closure, which is why we put `proxy_encode` and `proxy_decode`
/// behind `encode` and `decode` below.
#[allow(clippy::type_complexity)]
struct VersionedEncoding<T> {
    version_range: RangeInclusive<CertificationVersion>,
    name: &'static str,
    // Closure that invokes `CborProxyEncoder::proxy_encode()`. See above for why.
    encode: fn((&T, CertificationVersion)) -> Result<Vec<u8>, serde_cbor::Error>,
    // Closure that invokes `CborProxyDecoder::proxy_decode()`. See above for why.
    decode: fn(&[u8]) -> Result<T, ProxyDecodeError>,
}

impl<T> VersionedEncoding<T> {
    #[allow(clippy::type_complexity)]
    fn new(
        version_range: RangeInclusive<CertificationVersion>,
        name: &'static str,
        encode: fn((&T, CertificationVersion)) -> Result<Vec<u8>, serde_cbor::Error>,
        decode: fn(&[u8]) -> Result<T, ProxyDecodeError>,
    ) -> VersionedEncoding<T> {
        Self {
            version_range,
            name,
            encode,
            decode,
        }
    }
}

/// Produces a `StreamHeader` valid at all certification versions in the range.
pub(crate) fn arb_valid_versioned_stream_header(
    max_signal_count: usize,
) -> impl Strategy<Value = (StreamHeader, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        // Stream headers up to and including certification version 8 had no reject
        // signals.
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                /* max_signal_count */ 0,
                /* with_reject_reasons */ vec![],
                /* with_responses_only_flag */ vec![false],
            ),
            Just(CertificationVersion::V0..=CertificationVersion::V8)
        ),
        // Stream headers may have reject signals for responses (`CanisterMigrating` only)
        // starting with certification version 8.
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                max_signal_count,
                /* with_reject_reasons */ vec![RejectReason::CanisterMigrating],
                /* with_responses_only_flag */ vec![false],
            ),
            Just(CertificationVersion::V8..=CertificationVersion::V16)
        ),
        // Stream headers may have the `StreamHeaderFlagBits::DeprecatedResponsesOnly` flag set
        // starting with certification version 17.
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                max_signal_count,
                /* with_reject_reasons */ vec![RejectReason::CanisterMigrating],
                /* with_responses_only_flag */ vec![true, false],
            ),
            Just(CertificationVersion::V17..=CertificationVersion::V18)
        ),
        // Stream headers may have flavours of reject signals other than `CanisterMigrating`
        // starting from certification version 19.
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                max_signal_count,
                /* with_reject_reasons */
                vec![
                    RejectReason::CanisterMigrating,
                    RejectReason::CanisterNotFound,
                    RejectReason::CanisterStopped,
                    RejectReason::CanisterStopping,
                    RejectReason::QueueFull,
                    RejectReason::OutOfMemory,
                    RejectReason::Unknown
                ],
                /* with_responses_only_flag */ vec![true, false],
            ),
            Just(CertificationVersion::V19..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        )
    ]
}

/// Produces a `StreamHeader` invalid at all certification versions in the range.
pub(crate) fn arb_invalid_versioned_stream_header(
    max_signal_count: usize,
) -> impl Strategy<Value = (StreamHeader, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        // Encoding a stream header with non-empty reject signals before certification
        // version 8 should panic.
        (
            arb_stream_header(
                /* min_signal_count */ 1,
                max_signal_count,
                /* with_reject_reasons */ vec![RejectReason::CanisterMigrating],
                /* with_responses_only_flag */ vec![false],
            ),
            Just(CertificationVersion::V7..=CertificationVersion::V7)
        ),
        // Encoding a stream header with flags set before certification version 17
        // should panic.
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                max_signal_count,
                /* with_reject_reasons */ vec![RejectReason::CanisterMigrating],
                /* with_responses_only_flags */ vec![true],
            ),
            Just(CertificationVersion::V16..=CertificationVersion::V16)
        ),
        // Encoding a stream header with reject signal flavors other than `CanisterMigrating`
        // before certification version 19 should panic.
        (
            arb_stream_header(
                /* min_signal_count */ 1,
                max_signal_count,
                /* with_reject_reasons */
                vec![
                    RejectReason::CanisterNotFound,
                    RejectReason::CanisterStopped,
                    RejectReason::CanisterStopping,
                    RejectReason::QueueFull,
                    RejectReason::OutOfMemory,
                    RejectReason::Unknown,
                ],
                /* with_responses_only_flags */ vec![true, false],
            ),
            Just(CertificationVersion::V18..=CertificationVersion::V18)
        ),
    ]
}

lazy_static! {
    /// Current and previous canonical `StreamHeader` types and applicable
    /// certification versions.
    static ref STREAM_HEADER_ENCODINGS: Vec<VersionedEncoding<StreamHeader>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V6,
            "StreamHeaderV6",
            |v| StreamHeaderV6::proxy_encode(v),
            |v| StreamHeaderV6::proxy_decode(v),
        ),
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V16,
            "StreamHeaderV16",
            |v| StreamHeaderV16::proxy_encode(v),
            |v| StreamHeaderV16::proxy_decode(v),
        ),
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V18,
            "StreamHeaderV18",
            |v| StreamHeaderV18::proxy_encode(v),
            |v| StreamHeaderV18::proxy_decode(v),
        ),
        VersionedEncoding::new(
            CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "StreamHeader",
            |v| StreamHeaderV19::proxy_encode(v),
            |v| StreamHeaderV19::proxy_decode(v),
        ),
    ];
}

proptest! {
    /// Tests that given a `StreamHeader` that is valid for a given certification
    /// version range (e.g. no `reject_signals` before certification version 8) all
    /// supported canonical type (e.g. `StreamHeaderV6` or `StreamHeader`) and
    /// certification version combinations produce the exact same encoding.
    #[test]
    fn stream_header_unique_encoding((header, version_range) in arb_valid_versioned_stream_header(100)) {
        let mut results = vec![];
        for version in iter(version_range) {
            let results_before = results.len();
            for encoding in &*STREAM_HEADER_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&header, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    results.push((version, encoding.name, bytes));
                }
            }
            assert!(results.len() > results_before, "No supported encodings for certification version {:?}", version);
        }

        if results.len() > 1 {
            let (current_version, current_name, current_bytes) = results.pop().unwrap();
            for (version, name, bytes) in &results {
                assert_eq!(&current_bytes, bytes, "Different encodings: {}@{:?} and {}@{:?}", current_name, current_version, name, version);
            }
        }
    }

    /// Tests that, given a `StreamHeader` that is valid for a given certification
    /// version range (e.g. no `reject_signals` before certification version 8),
    /// all supported encodings will decode back into the same `StreamHeader`.
    #[test]
    fn stream_header_roundtrip_encoding((header, version_range) in arb_valid_versioned_stream_header(100)) {
        for version in iter(version_range) {
            for encoding in &*STREAM_HEADER_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&header, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    let result = (encoding.decode)(&bytes)
                        .unwrap_or_else(|_| panic!("Failed to decode {}@{:?}", encoding.name, version));

                    assert_eq!(header, result, "Roundtrip encoding {}@{:?} failed", encoding.name, version);
                }
            }
        }
    }

    /// Tests that, given a `StreamHeader` that is invalid for a given certification
    /// version range (e.g. `reject_signals` before certification version 8),
    /// encoding will panic.
    ///
    /// Be aware that the output generated by this test failing includes all panics
    /// (e.g. stack traces), including those produced by previous iterations where
    /// panics were caught by `std::panic::catch_unwind`.
    #[test]
    fn stream_header_encoding_panic_on_invalid((header, version_range) in arb_invalid_versioned_stream_header(100)) {
        for version in iter(version_range) {
            for encoding in &*STREAM_HEADER_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let result = std::panic::catch_unwind(|| {
                        (encoding.encode)((&header, version))
                    });

                    assert!(result.is_err(), "Encoding of invalid {}@{:?} succeeded", encoding.name, version);
                }
            }
        }
    }
}

/// Produces a `RequestOrResponse` valid at all certification versions in the range.
pub(crate) fn arb_valid_versioned_message(
) -> impl Strategy<Value = (RequestOrResponse, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        (
            // No `Request::metadata` populated for versions 13 and below.
            arbitrary::request_or_response_with_config(false, false),
            Just(CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
        (
            // Optionally populate `Request::metadata` from version 14 on.
            arbitrary::request_or_response_with_config(true, false),
            Just(CertificationVersion::V14..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
        (
            // Optionally populate `deadline` from version 18 on.
            arbitrary::request_or_response_with_config(true, true),
            Just(CertificationVersion::V18..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
    ]
}

lazy_static! {
    /// Current and previous canonical `RequestOrResponse` types and applicable
    /// certification versions.
    static ref MESSAGE_ENCODINGS: Vec<VersionedEncoding<RequestOrResponse>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V3,
            "RequestOrResponseV3",
            |v| RequestOrResponseV3::proxy_encode(v),
            |v| RequestOrResponseV3::proxy_decode(v),
        ),
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V13,
            "RequestOrResponseV13",
            |v| RequestOrResponseV13::proxy_encode(v),
            |v| RequestOrResponseV13::proxy_decode(v),
        ),
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V17,
            "RequestOrResponseV17",
            |v| RequestOrResponseV17::proxy_encode(v),
            |v| RequestOrResponseV17::proxy_decode(v),
        ),
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "RequestOrResponse",
            |v| RequestOrResponseV18::proxy_encode(v),
            |v| RequestOrResponseV18::proxy_decode(v),
        ),
    ];
}

proptest! {
    /// Tests that given a `RequestOrResponse` that is valid for a given certification
    /// version range (e.g. no `reject_signals` before certification version 8) all
    /// supported canonical type (e.g. `RequestOrResponseV3` or `RequestOrResponse`)
    /// and certification version combinations produce the exact same encoding.
    #[test]
    fn message_unique_encoding((message, version_range) in arb_valid_versioned_message()) {
        let mut results = vec![];
        for version in iter(version_range) {
            let results_before = results.len();
            for encoding in &*MESSAGE_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&message, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    results.push((version, encoding.name, bytes));
                }
            }
            assert!(results.len() > results_before, "No supported encodings for certification version {:?}", version);
        }

        if results.len() > 1 {
            let (current_version, current_name, current_bytes) = results.pop().unwrap();
            for (version, name, bytes) in &results {
                assert_eq!(&current_bytes, bytes, "Different encodings: {}@{:?} and {}@{:?}", current_name, current_version, name, version);
            }
        }
    }

    /// Tests that, given a `RequestOrResponse` that is valid for a given
    /// certification version range, all supported encodings will decode back into
    /// the same `RequestOrResponse`.
    #[test]
    fn message_roundtrip_encoding((message, version_range) in arb_valid_versioned_message()) {
        for version in iter(version_range) {
            for encoding in &*MESSAGE_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&message, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    let result = (encoding.decode)(&bytes)
                        .unwrap_or_else(|_| panic!("Failed to decode {}@{:?}", encoding.name, version));

                    assert_eq!(message, result, "Roundtrip encoding {}@{:?} failed", encoding.name, version);
                }
            }
        }
    }
}

lazy_static! {
    /// Current and previous canonical `SystemMetadata` types and applicable
    /// certification versions.
    static ref SYSTEM_METADATA_ENCODINGS: Vec<VersionedEncoding<SystemMetadata>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V9,
            "SystemMetadataV9",
            |v| SystemMetadataV9::proxy_encode(v),
            |_v| unimplemented!(),
        ),
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "SystemMetadataV10",
            |v| SystemMetadataV10::proxy_encode(v),
            |_v| unimplemented!(),
        ),
    ];
}

prop_compose! {
    /// Returns an arbitrary [`SystemMetadata`] (with only the fields relevant to
    /// its canonical representation filled).
    pub fn arb_system_metadata()(
        prev_state_hash in prop::collection::vec(any::<u8>(), 32)
    ) -> SystemMetadata {
        let mut metadata = SystemMetadata::new(
            PrincipalId::new_subnet_test_id(1).into(),
            ic_registry_subnet_type::SubnetType::Application
        );
        metadata.prev_state_hash = Some(CryptoHashOfPartialState::new(CryptoHash(prev_state_hash)));
        metadata
    }
}

/// Produces a `SystemMetadata` valid at all certification versions in the range.
///
/// Returns one of two disjoint version ranges, because the encoding of the same
/// `SystemMetadata` is different between the two version ranges.
///
pub(crate) fn arb_valid_system_metadata(
) -> impl Strategy<Value = (SystemMetadata, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        // `SystemMetadata` up to and including `V9` had a required `id_counter` field.
        (
            arb_system_metadata(),
            Just(CertificationVersion::V0..=CertificationVersion::V9)
        ),
        // `SystemMetadata` `V10` and later have an optional `id_counter` field for
        // backwards compatibility, but it is no longer populated.
        (
            arb_system_metadata(),
            Just(CertificationVersion::V10..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
    ]
}

proptest! {
    /// Tests that given a `SystemMetadata` that is valid for a given certification
    /// version range, all supported canonical type (e.g. `SystemMetadataV9` or
    /// `SystemMetadataV10`) and certification version combinations produce the
    /// exact same encoding.
    #[test]
    fn system_metadata_unique_encoding((metadata, version_range) in arb_valid_system_metadata()) {
        let mut results = vec![];
        for version in iter(version_range) {
            let results_before = results.len();
            for encoding in &*SYSTEM_METADATA_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&metadata, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    results.push((version, encoding.name, bytes));
                }
            }
            assert!(results.len() > results_before, "No supported encodings for certification version {:?}", version);
        }

        if results.len() > 1 {
            let (current_version, current_name, current_bytes) = results.pop().unwrap();
            for (version, name, bytes) in &results {
                assert_eq!(&current_bytes, bytes, "Different encodings: {}@{:?} and {}@{:?}", current_name, current_version, name, version);
            }
        }
    }
}

lazy_static! {
    /// Current and previous canonical `SubnetMetrics` types and applicable
    /// certification versions.
    static ref SUBNET_METRICS_ENCODINGS: Vec<VersionedEncoding<SubnetMetrics>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V15..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "SubnetMetricsV15",
            |v| SubnetMetricsV15::proxy_encode(v),
            |_v| unimplemented!(),
        ),
    ];
}

/// Produces a `SubnetMetrics` valid at all certification versions in the range.
pub(crate) fn arb_valid_subnet_metrics(
) -> impl Strategy<Value = (SubnetMetrics, RangeInclusive<CertificationVersion>)> {
    prop_oneof![(
        arb_subnet_metrics(),
        Just(CertificationVersion::V15..=MAX_SUPPORTED_CERTIFICATION_VERSION)
    )]
}

proptest! {
    /// Tests that given a `SubnetMetrics` that is valid for a given certification
    /// version range, all supported canonical type and certification version
    /// combinations produce the exact same encoding.
    #[test]
    fn subnet_metrics_unique_encoding((subnet_metrics, version_range) in arb_valid_subnet_metrics()) {
        let mut results = vec![];
        for version in iter(version_range) {
            let results_before = results.len();
            for encoding in &*SUBNET_METRICS_ENCODINGS {
                if encoding.version_range.contains(&version) {
                    let bytes = (encoding.encode)((&subnet_metrics, version))
                        .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                    results.push((version, encoding.name, bytes));
                }
            }
            assert!(results.len() > results_before, "No supported encodings for certification version {:?}", version);
        }

        if results.len() > 1 {
            let (current_version, current_name, current_bytes) = results.pop().unwrap();
            for (version, name, bytes) in &results {
                assert_eq!(&current_bytes, bytes, "Different encodings: {}@{:?} and {}@{:?}", current_name, current_version, name, version);
            }
        }
    }
}

fn iter(
    version_range: RangeInclusive<CertificationVersion>,
) -> impl Iterator<Item = CertificationVersion> {
    CertificationVersion::iter().filter(move |v| version_range.contains(v))
}
