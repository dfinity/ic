use ic_canonical_state::{
    encoding::{
        old_types::{RequestOrResponseV3, StreamHeaderV6},
        types::{RequestOrResponse as RequestOrResponseV4, StreamHeader as StreamHeaderV8},
        *,
    },
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION,
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_test_utilities::{state::arb_stream_header, types::arbitrary};
use ic_types::{messages::RequestOrResponse, xnet::StreamHeader};
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::ops::RangeInclusive;
use strum::IntoEnumIterator;

/// A named combination of canonical type; and the certification version range
/// that it may be applied within; for encoding and decoding values of type `T`.
///
/// E.g. `StreamHeaderV6` may be used for encoding and decoding `StreamHeader`
/// values for any certification version in range `0..=6`.
#[allow(clippy::type_complexity)]
struct VersionedEncoding<T> {
    version_range: RangeInclusive<CertificationVersion>,
    name: &'static str,
    encode: fn((&T, CertificationVersion)) -> Result<Vec<u8>, serde_cbor::Error>,
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
    sig_max_size: usize,
) -> impl Strategy<Value = (StreamHeader, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        // Stream headers up to and including certification version 8 had no reject
        // signals.
        (
            arb_stream_header(/* sig_min_size */ 0, /* sig_max_size */ 0),
            Just(CertificationVersion::V0..=CertificationVersion::V8)
        ),
        // Stream headers may have reject signals starting with certification version
        // 8.
        (
            arb_stream_header(/* sig_min_size */ 0, sig_max_size),
            Just(CertificationVersion::V8..=CertificationVersion::V9)
        ),
    ]
}

/// Produces a `StreamHeader` invalid at all certification versions in the range.
pub(crate) fn arb_invalid_versioned_stream_header(
    sig_max_size: usize,
) -> impl Strategy<Value = (StreamHeader, RangeInclusive<CertificationVersion>)> {
    prop_oneof![
        // Encoding a stream header with non-empty reject signals before certification
        // version 8 should panic.
        (
            arb_stream_header(/* sig_min_size */ 1, sig_max_size),
            Just(CertificationVersion::V7..=CertificationVersion::V7)
        ),
    ]
}

lazy_static! {
    // Per https://stackoverflow.com/questions/67342223/one-type-function-pointer-is-more-general-than-the-other
    // the Rust compiler is unable to "automatically convert generic functions
    // which include a type bounded by a lifetime into a function pointer that
    // is fully generic over that lifetime".
    //
    // The recommended workaround is to wrap the generic call within a
    // non-generic closure, which is what we do with `proxy_encode` and
    // `proxy_decode` below.
    static ref STREAM_HEADER_ENCODINGS: Vec<VersionedEncoding<StreamHeader>> = vec![
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V6,
            "StreamHeaderV6",
            |v| StreamHeaderV6::proxy_encode(v),
            |v| StreamHeaderV6::proxy_decode(v),
        ),
        #[allow(clippy::redundant_closure)]
        VersionedEncoding::new(
            CertificationVersion::V0..=CertificationVersion::V9,
            "StreamHeader",
            |v| StreamHeaderV8::proxy_encode(v),
            |v| StreamHeaderV8::proxy_decode(v),
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

    /// Tests that, given a `StreamHeader` that is valid for a given certification
    /// version range (e.g. no `reject_signals` before certification version 8),
    /// all supported encodings will decode back into the same `StreamHeader`.
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
    prop_oneof![(
        arbitrary::request_or_response(),
        Just(CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION)
    ),]
}

lazy_static! {
    // Per https://stackoverflow.com/questions/67342223/one-type-function-pointer-is-more-general-than-the-other
    // the Rust compiler is unable to "automatically convert generic functions
    // which include a type bounded by a lifetime into a function pointer that
    // is fully generic over that lifetime".
    //
    // The recommended workaround is to wrap the generic call within a
    // non-generic closure, which is what we do with `proxy_encode` and
    // `proxy_decode` below.
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
            CertificationVersion::V0..=MAX_SUPPORTED_CERTIFICATION_VERSION,
            "RequestOrResponse",
            |v| RequestOrResponseV4::proxy_encode(v),
            |v| RequestOrResponseV4::proxy_decode(v),
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
    fn message_roundtrip_encoding((header, version_range) in arb_valid_versioned_message()) {
        for version in iter(version_range) {
            for encoding in &*MESSAGE_ENCODINGS {
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
}

fn iter(
    version_range: RangeInclusive<CertificationVersion>,
) -> impl Iterator<Item = CertificationVersion> {
    CertificationVersion::iter().filter(move |v| version_range.contains(v))
}
