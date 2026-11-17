use ic_canonical_state::{
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION, MIN_SUPPORTED_CERTIFICATION_VERSION,
    encoding::{
        CborProxyDecoder, CborProxyEncoder,
        types::{
            StreamHeader as StreamHeaderV26, StreamMessage as StreamMessageV23,
            SubnetMetrics as SubnetMetricsV21,
        },
    },
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_replicated_state::metadata_state::SubnetMetrics;
use ic_test_utilities_state::{arb_invalid_stream_header, arb_stream_header, arb_subnet_metrics};
use ic_test_utilities_types::arbitrary;
use ic_types::{
    messages::StreamMessage,
    xnet::{RejectReason, StreamHeader},
};
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::ops::RangeInclusive;
use strum::IntoEnumIterator;

/// A named combination of canonical type; and the certification version range
/// that it may be applied within; for encoding and decoding values of type `T`.
///
/// E.g. if certification version `V31` changed the canonical `StreamHeader`,
/// the previous canonical type would be moved to `old_types` (as e.g.
/// `StreamHeaderV30`) and remain applicable within `..=V30`; while the new
/// canonical `StreamHeader` would be applicable to all supported versions. The
/// `*_ENCODINGS` collections below then hold both, and the tests check that they
/// produce the same encoding at every version that both apply to. Values that
/// only the new canonical type can encode (e.g. a new field or enum variant) are
/// produced by a separate `arb_*` strategy arm whose version range starts at
/// `V31`; while the existing arm must then exclude them (e.g. leave the new field
/// unset), so that its values remain valid at all supported versions. The
/// `*_ENCODINGS` collections and `arb_*` strategies below each contain a
/// commented-out example of such an addition.
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
        (
            arb_stream_header(
                /* min_signal_count */ 0,
                max_signal_count,
                /* with_reject_reasons */ RejectReason::all(),
            ),
            Just(MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
        // Headers that are only valid starting with a newer certification version,
        // e.g. if `V31` added a new `RejectReason` (which the arm above must then
        // exclude, so that its headers remain valid at all supported versions):
        //
        // (
        //     arb_stream_header(
        //         /* min_signal_count */ 0,
        //         max_signal_count,
        //         /* with_reject_reasons */ RejectReason::all(),
        //     ),
        //     Just(CertificationVersion::V31..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        // ),
    ]
}

/// Produces a `StreamHeader` invalid at all certification versions in the range.
pub(crate) fn arb_invalid_versioned_stream_header(
    max_signal_count: usize,
) -> impl Strategy<Value = (StreamHeader, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        (
            arb_invalid_stream_header(
                /* min_signal_count */ 1,
                max_signal_count,
                /* with_reject_reasons */ RejectReason::all(),
            ),
            Just(MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION),
        ),
        // Headers that are only invalid up to some certification version, e.g. if
        // `V31` added a new `RejectReason` (which the arm above must then exclude,
        // so that its headers remain invalid at all supported versions), headers
        // using it would be invalid before `V31`:
        //
        // (
        //     arb_stream_header(
        //         /* min_signal_count */ 1,
        //         max_signal_count,
        //         /* with_reject_reasons */ vec![RejectReason::NewReason],
        //     ),
        //     Just(MIN_SUPPORTED_CERTIFICATION_VERSION..=CertificationVersion::V30),
        // ),
    ]
}

lazy_static! {
    /// Current and previous canonical `StreamHeader` types and applicable
    /// certification versions.
    static ref STREAM_HEADER_ENCODINGS: Vec<VersionedEncoding<StreamHeader>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "StreamHeader",
            |v| StreamHeaderV26::proxy_encode(v),
            |v| StreamHeaderV26::proxy_decode(v),
        ),
        // Previous canonical type, applicable up to the last certification
        // version that used it, e.g.:
        //
        // VersionedEncoding::new(
        //     MIN_SUPPORTED_CERTIFICATION_VERSION..=CertificationVersion::V30,
        //     "StreamHeaderV30",
        //     |v| StreamHeaderV30::proxy_encode(v),
        //     |v| StreamHeaderV30::proxy_decode(v),
        // ),
    ];
}

/// Tests that, given a `StreamHeader` that is valid for a given certification
/// version range, all canonical types in `STREAM_HEADER_ENCODINGS` that are
/// applicable to a given certification version produce the exact same encoding.
#[test_strategy::proptest]
fn stream_header_unique_encoding(
    #[strategy(arb_valid_versioned_stream_header(
        100, // max_signal_count
    ))]
    test_header: (StreamHeader, RangeInclusive<CertificationVersion>),
) {
    let (header, version_range) = test_header;

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
        prop_assert!(
            results.len() > results_before,
            "No supported encodings for certification version {version:?}"
        );
    }

    if results.len() > 1 {
        let (current_version, current_name, current_bytes) = results.pop().unwrap();
        for (version, name, bytes) in &results {
            if version == &current_version {
                prop_assert_eq!(
                    &current_bytes,
                    bytes,
                    "Different encodings: {}@{:?} and {}@{:?}",
                    current_name,
                    current_version,
                    name,
                    version
                );
            }
        }
    }
}

/// Tests that, given a `StreamHeader` that is valid for a given certification
/// version range, all supported encodings will decode back into the same
/// `StreamHeader`.
#[test_strategy::proptest]
fn stream_header_roundtrip_encoding(
    #[strategy(arb_valid_versioned_stream_header(
        100, // max_signal_count
    ))]
    test_header: (StreamHeader, RangeInclusive<CertificationVersion>),
) {
    let (header, version_range) = test_header;

    for version in iter(version_range) {
        for encoding in &*STREAM_HEADER_ENCODINGS {
            if encoding.version_range.contains(&version) {
                let bytes = (encoding.encode)((&header, version))
                    .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                let result = (encoding.decode)(&bytes)
                    .unwrap_or_else(|_| panic!("Failed to decode {}@{:?}", encoding.name, version));

                prop_assert_eq!(
                    &header,
                    &result,
                    "Roundtrip encoding {}@{:?} failed",
                    encoding.name,
                    version
                );
            }
        }
    }
}

/// Tests that, given a `StreamHeader` that is invalid for a given certification
/// version range (e.g. with a reject signal at `signals_end`), encoding will
/// panic.
///
/// Be aware that the output generated by this test failing includes all panics
/// (e.g. stack traces), including those produced by previous iterations where
/// panics were caught by `std::panic::catch_unwind`.
#[test_strategy::proptest]
fn stream_header_encoding_panic_on_invalid(
    #[strategy(arb_invalid_versioned_stream_header(
        100, // max_signal_count
    ))]
    test_header: (StreamHeader, RangeInclusive<CertificationVersion>),
) {
    let (header, version_range) = test_header;
    for version in iter(version_range) {
        for encoding in &*STREAM_HEADER_ENCODINGS {
            if encoding.version_range.contains(&version) {
                let result = std::panic::catch_unwind(|| (encoding.encode)((&header, version)));

                prop_assert!(
                    result.is_err(),
                    "Encoding of invalid {}@{:?} succeeded",
                    encoding.name,
                    version
                );
            }
        }
    }
}

/// Produces a `StreamMessage` valid at all certification versions in the range.
pub(crate) fn arb_valid_versioned_message()
-> impl Strategy<Value = (StreamMessage, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        (
            arbitrary::stream_message_with_config(true),
            Just(MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
        // Messages that are only valid starting with a newer certification version,
        // e.g. if `V31` added a new field (which the arm above must then leave
        // unset, so that its messages remain valid at all supported versions):
        //
        // (
        //     arb_stream_message_with_new_field(),
        //     Just(CertificationVersion::V31..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        // ),
    ]
}

lazy_static! {
    /// Current and previous canonical `StreamMessage` types and applicable
    /// certification versions.
    static ref MESSAGE_ENCODINGS: Vec<VersionedEncoding<StreamMessage>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "StreamMessage",
            |v| StreamMessageV23::proxy_encode(v),
            |v| StreamMessageV23::proxy_decode(v),
        ),
        // Previous canonical type, applicable up to the last certification
        // version that used it, e.g.:
        //
        // VersionedEncoding::new(
        //     MIN_SUPPORTED_CERTIFICATION_VERSION..=CertificationVersion::V30,
        //     "StreamMessageV30",
        //     |v| StreamMessageV30::proxy_encode(v),
        //     |v| StreamMessageV30::proxy_decode(v),
        // ),
    ];
}

/// Tests that, given a `StreamMessage` that is valid for a given certification
/// version range, all canonical types in `MESSAGE_ENCODINGS` that are applicable
/// to a given certification version produce the exact same encoding.
#[test_strategy::proptest]
fn message_unique_encoding(
    #[strategy(arb_valid_versioned_message())] test_message: (
        StreamMessage,
        RangeInclusive<CertificationVersion>,
    ),
) {
    let (message, version_range) = test_message;

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
        prop_assert!(
            results.len() > results_before,
            "No supported encodings for certification version {version:?}"
        );
    }

    if results.len() > 1 {
        let (current_version, current_name, current_bytes) = results.pop().unwrap();
        for (version, name, bytes) in &results {
            if version == &current_version {
                prop_assert_eq!(
                    &current_bytes,
                    bytes,
                    "Different encodings: {}@{:?} and {}@{:?}",
                    current_name,
                    current_version,
                    name,
                    version
                );
            }
        }
    }
}

/// Tests that, given a `StreamMessage` that is valid for a given
/// certification version range, all supported encodings will decode back into
/// the same `StreamMessage`.
#[test_strategy::proptest]
fn message_roundtrip_encoding(
    #[strategy(arb_valid_versioned_message())] test_message: (
        StreamMessage,
        RangeInclusive<CertificationVersion>,
    ),
) {
    let (message, version_range) = test_message;

    for version in iter(version_range) {
        for encoding in &*MESSAGE_ENCODINGS {
            if encoding.version_range.contains(&version) {
                let bytes = (encoding.encode)((&message, version))
                    .unwrap_or_else(|_| panic!("Failed to encode {}@{:?}", encoding.name, version));
                let result = (encoding.decode)(&bytes)
                    .unwrap_or_else(|_| panic!("Failed to decode {}@{:?}", encoding.name, version));

                prop_assert_eq!(
                    &message,
                    &result,
                    "Roundtrip encoding {}@{:?} failed",
                    encoding.name,
                    version
                );
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
            MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "SubnetMetricsV21",
            |(metrics, version)| SubnetMetricsV21::proxy_encode((metrics, version)),
            |_v| unimplemented!(),
        ),
        // Previous canonical type, applicable up to the last certification
        // version that used it, e.g.:
        //
        // VersionedEncoding::new(
        //     MIN_SUPPORTED_CERTIFICATION_VERSION..=CertificationVersion::V30,
        //     "SubnetMetricsV30",
        //     |(metrics, version)| SubnetMetricsV30::proxy_encode((metrics, version)),
        //     |_v| unimplemented!(),
        // ),
    ];
}

/// Produces a `SubnetMetrics` valid at all certification versions in the range.
pub(crate) fn arb_valid_subnet_metrics()
-> impl Strategy<Value = (SubnetMetrics, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        (
            arb_subnet_metrics(),
            Just(MIN_SUPPORTED_CERTIFICATION_VERSION..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        ),
        // Metrics that are only valid starting with a newer certification version,
        // e.g. if `V31` added a new metric (which the arm above must then leave
        // unset, so that its metrics remain valid at all supported versions):
        //
        // (
        //     arb_subnet_metrics_with_new_metric(),
        //     Just(CertificationVersion::V31..=MAX_SUPPORTED_CERTIFICATION_VERSION)
        // ),
    ]
}

/// Tests that given a `SubnetMetrics` that is valid for a given certification
/// version range, all supported canonical type and certification version
/// combinations produce the exact same encoding.
#[test_strategy::proptest]
fn subnet_metrics_unique_encoding(
    #[strategy(arb_valid_subnet_metrics())] test_subnet_metrics: (
        SubnetMetrics,
        RangeInclusive<CertificationVersion>,
    ),
) {
    let (subnet_metrics, version_range) = test_subnet_metrics;

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
        prop_assert!(
            results.len() > results_before,
            "No supported encodings for certification version {version:?}"
        );
    }

    if results.len() > 1 {
        let (current_version, current_name, current_bytes) = results.pop().unwrap();
        for (version, name, bytes) in &results {
            if version == &current_version {
                prop_assert_eq!(
                    &current_bytes,
                    bytes,
                    "Different encodings: {}@{:?} and {}@{:?}",
                    current_name,
                    current_version,
                    name,
                    version
                );
            }
        }
    }
}

fn iter(
    version_range: RangeInclusive<CertificationVersion>,
) -> impl Iterator<Item = CertificationVersion> {
    CertificationVersion::iter().filter(move |v| version_range.contains(v))
}
