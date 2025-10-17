//! Collection of canonical tree leaf backwards-compatibility tests.
//!
//! Any breakage of these tests likely means that the canonical state
//! representation and/or the XNet messaging protocol have changed and may no
//! longer be backwards-compatible.
//!
//! Such changes must be rolled out in stages, in order to maintain backwards
//! (and ideally forwards) compatibility with one or more preceding
//! protocol versions.

use crate::{CertificationVersion, all_supported_versions, encoding::*};
use assert_matches::assert_matches;
use ic_error_types::RejectCode;
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::system_state::CyclesUseCase,
    metadata_state::{SubnetMetrics, SystemMetadata},
};
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
use ic_types::{
    CryptoHashOfPartialState, Cycles, Funds, NumBytes, Time,
    crypto::CryptoHash,
    messages::{
        CallbackId, NO_DEADLINE, Payload, Refund, RejectContext, Request, RequestMetadata,
        Response, StreamMessage,
    },
    nominal_cycles::NominalCycles,
    time::CoarseTime,
    xnet::{RejectReason, RejectSignal, StreamFlags, StreamIndex},
};
use serde_cbor::value::Value;
use std::collections::{BTreeMap, VecDeque};

//
// Tests for exact binary encoding
//

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamHeader {
///     begin: 23.into(),
///     end: 25.into(),
///     signals_end: 256.into(),
///     reject_signals: VecDeque::new(),
///     flags: StreamFlags::default(),
/// }
/// ```
///
/// Expected:
///
/// ```text
/// A3         # map(3)
///    00      # field_index(StreamHeader::begin)
///    17      # unsigned(23)
///    01      # field_index(StreamHeader::end)
///    18 19   # unsigned(25)
///    02      # field_index(StreamHeader::signals_end)
///    19 0100 # unsigned(256)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_minimal_stream_header() {
    for certification_version in all_supported_versions() {
        let header = StreamHeader::new(
            23.into(),
            25.into(),
            256.into(),
            VecDeque::new(),
            StreamFlags::default(),
        );

        assert_eq!(
            "A3 00 17 01 18 19 02 19 01 00",
            as_hex(&encode_stream_header(&header, certification_version,))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamHeader {
///     begin: 23.into(),
///     end: 25.into(),
///     signals_end: 256.into(),
///     reject_signals: vec![
///         RejectSignal::new(RejectReason::CanisterMigrating, 249.into()),
///         RejectSignal::new(RejectReason::CanisterNotFound, 250.into()),
///         RejectSignal::new(RejectReason::QueueFull, 251.into()),
///         RejectSignal::new(RejectReason::OutOfMemory, 252.into()),
///         RejectSignal::new(RejectReason::CanisterStopping, 253.into()),
///         RejectSignal::new(RejectReason::CanisterStopped, 254.into()),
///         RejectSignal::new(RejectReason::Unknown, 255.into()),
///     ]
///     .into(),
///     flags: StreamFlags {
///        deprecated_responses_only: true,
///     },
/// }
/// ```
///
/// Expected:
///
/// ```text
/// A5          # map(5)
///    00       # field_index(StreamHeader::begin)
///    17       # unsigned(23)
///    01       # field_index(StreamHeader::end)
///    18 19    # unsigned(25)
///    02       # field_index(StreamHeader::signals_end)
///    19 0100  # unsigned(256)
///    04       # field_index(StreamHeader::flags)
///    01       # unsigned(1)
///    05       # field_index(StreamHeader::reject_signals)
///    A7       # map(7)
///       00    # field_index(RejectSignals::canister_migrating_deltas)
///       81    # array(1)
///          07 # unsigned(7)
///       01    # field_index(RejectSignals::canister_not_found_deltas)
///       81    # array(1)
///          06 # unsigned(6)
///       02    # field_index(RejectSignals::canister_stopped_deltas)
///       81    # array(1)
///          02 # unsigned(2)
///       03    # field_index(RejectSignals::canister_stopping_deltas)
///       81    # array(1)
///          03 # unsigned(3)
///       04    # field_index(RejectSignals::queue_full_deltas)
///       81    # array(1)
///          05 # unsigned(5)
///       05    # field_index(RejectSignals::out_of_memory_deltas)
///       81    # array(1)
///          04 # unsigned(4)
///       06    # field_index(RejectSignals::unknown_deltas)
///       81    # array(1)
///          01 # unsigned(1)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_stream_header() {
    for certification_version in all_supported_versions() {
        let header = StreamHeader::new(
            23.into(),
            25.into(),
            256.into(),
            vec![
                RejectSignal::new(RejectReason::CanisterMigrating, 249.into()),
                RejectSignal::new(RejectReason::CanisterNotFound, 250.into()),
                RejectSignal::new(RejectReason::QueueFull, 251.into()),
                RejectSignal::new(RejectReason::OutOfMemory, 252.into()),
                RejectSignal::new(RejectReason::CanisterStopping, 253.into()),
                RejectSignal::new(RejectReason::CanisterStopped, 254.into()),
                RejectSignal::new(RejectReason::Unknown, 255.into()),
            ]
            .into(),
            StreamFlags {
                deprecated_responses_only: true,
            },
        );

        assert_eq!(
            "A5 00 17 01 18 19 02 19 01 00 04 01 05 A7 00 81 07 01 81 06 02 81 02 03 81 03 04 81 05 05 81 04 06 81 01",
            as_hex(&encode_stream_header(&header, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// SubnetMetrics {
///     consumed_cycles_by_deleted_canisters: 0.into(),
///     consumed_cycles_http_outcalls: 50_000_000_000.into(),
///     consumed_cycles_ecdsa_outcalls: 100_000_000_000.into(),
///     consumed_cycles_by_use_case: btreemap! {
///         CyclesUseCase::Instructions => 80_000_000_000.into(),
///         CyclesUseCase::RequestAndResponseTransmission => 20_000_000_000.into(),
///     },
///     num_canisters: 5,
///     canister_state_bytes: (5 * 1024 * 1024).into(),
///     update_transactions_total: 4200,
///     threshold_signature_agreements: btreemap!{
///         schnorr_key_id => 15,
///         ecdsa_key_id => 16,
///     }
/// }
/// ```
///
/// Expected:
///
/// For the `consumed_cycles_total`, the expected value (250B) is the sum of all
/// the invividual values above.
///
/// ```text
/// A4                        # map(4)
///    00                     # field_index(SubnetMetrics::num_canisters)
///    05                     # unsigned(5)
///    01                     # field_index(SubnetMetrics::canister_state_bytes)
///    1A 00500000            # unsigned(5242880)
///    02                     # field_index(SubnetMetrics::consumed_cycles_total)
///    A2                     # map(2)
///       00                  # field_index(Cycles::low)
///       1B 0000003A35294400 # unsigned(250000000000)
///       01                  # field_index(Cycles:high)
///       00                  # unsigned(0)
///    03                     # field_index(SubnetMetrics::update_transactions_total)
///    19 1068                # unsigned(4200)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_subnet_metrics() {
    for certification_version in all_supported_versions() {
        let mut metrics = SubnetMetrics::default();
        metrics.consumed_cycles_by_deleted_canisters = NominalCycles::from(0);
        metrics.consumed_cycles_http_outcalls = NominalCycles::from(50_000_000_000);
        metrics.consumed_cycles_ecdsa_outcalls = NominalCycles::from(100_000_000_000);
        metrics.num_canisters = 5;
        metrics.canister_state_bytes = NumBytes::from(5 * 1024 * 1024);
        metrics.update_transactions_total = 4200;
        metrics.observe_consumed_cycles_with_use_case(
            CyclesUseCase::Instructions,
            NominalCycles::from(80_000_000_000),
        );
        metrics.observe_consumed_cycles_with_use_case(
            CyclesUseCase::RequestAndResponseTransmission,
            NominalCycles::from(20_000_000_000),
        );
        let schnorr_key_id = MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "schnorr_key_id".into(),
        });
        let ecdsa_key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "ecdsa_key_id".into(),
        });
        metrics.threshold_signature_agreements =
            BTreeMap::from([(schnorr_key_id, 15), (ecdsa_key_id, 16)]);

        assert_eq!(
            "A4 00 05 01 1A 00 50 00 00 02 A2 00 1B 00 00 00 3A 35 29 44 00 01 00 03 19 10 68",
            as_hex(&encode_subnet_metrics(&metrics, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Request(
///     Request {
///         receiver: canister_test_id(1),
///         sender: canister_test_id(2),
///         sender_reply_callback: CallbackId::from(3),
///         payment: Cycles::new(3),
///         method_name: "test".to_string(),
///         method_payload: vec![6],
///         metadata: Some(RequestMetadata {
///             call_tree_depth: 13,
///             call_tree_start_time: Time::as_nanos_since_unix_epoch(101),
///         }),
///         deadline: NO_DEADLINE,
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    00                         # field_index(StreamMessage::request)
///    A7                         # map(7)
///       00                      # field_index(Request::receiver)
///       4A                      # bytes(10)
///          00000000000000010101 # "\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01"
///       01                      # field_index(Request::sender)
///       4A                      # bytes(10)
///          00000000000000020101 # "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01"
///       02                      # field_index(Request::sender_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Request::payment)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A1                   # map(1)
///             00                # field_index(Cycles::low)
///             04                # unsigned(4)
///       04                      # field_index(Request::method_name)
///       64                      # text(4)
///          74657374             # "test"
///       05                      # field_index(Request::method_payload)
///       41                      # bytes(1)
///          06                   # "\x06"
///       07                      # field_index(Request::metadata)
///       A2                      # map(2)
///          00                   # field_index(RequestMetadata::call_tree_depth)
///          0D                   # unsigned(13)
///          01                   # field_index(RequestMetadata::call_tree_start_time)
///          18 65                # unsigned(101)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_minimal_request() {
    for certification_version in all_supported_versions() {
        let request: StreamMessage = Request {
            receiver: canister_test_id(1),
            sender: canister_test_id(2),
            sender_reply_callback: CallbackId::from(3),
            payment: Cycles::new(4),
            method_name: "test".to_string(),
            method_payload: vec![6],
            metadata: RequestMetadata::new(13, Time::from_nanos_since_unix_epoch(101)),
            deadline: NO_DEADLINE,
        }
        .into();

        assert_eq!(
            "A1 00 A7 00 4A 00 00 00 00 00 00 00 01 01 01 01 4A 00 00 00 00 00 00 00 02 01 01 02 03 03 A1 00 A1 00 04 04 64 74 65 73 74 05 41 06 07 A2 00 0D 01 18 65",
            as_hex(&encode_message(&request, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Request(
///     Request {
///         receiver: canister_test_id(1),
///         sender: canister_test_id(2),
///         sender_reply_callback: CallbackId::from(3),
///         payment: Cycles::new(3),
///         method_name: "test".to_string(),
///         method_payload: vec![6],
///         metadata: Some(RequestMetadata {
///             call_tree_depth: 13,
///             call_tree_start_time: Time::as_nanos_since_unix_epoch(101),
///         }),
///         deadline: CoarseTime(8),
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    00                         # field_index(StreamMessage::request)
///    A8                         # map(8)
///       00                      # field_index(Request::receiver)
///       4A                      # bytes(10)
///          00000000000000010101 # "\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01"
///       01                      # field_index(Request::sender)
///       4A                      # bytes(10)
///          00000000000000020101 # "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01"
///       02                      # field_index(Request::sender_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Request::payment)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A1                   # map(1)
///             00                # field_index(Cycles::low)
///             04                # unsigned(4)
///       04                      # field_index(Request::method_name)
///       64                      # text(4)
///          74657374             # "test"
///       05                      # field_index(Request::method_payload)
///       41                      # bytes(1)
///          06                   # "\x06"
///       07                      # field_index(Request::metadata)
///       A2                      # map(2)
///          00                   # field_index(RequestMetadata::call_tree_depth)
///          0D                   # unsigned(13)
///          01                   # field_index(RequestMetadata::call_tree_start_time)
///          18 65                # unsigned(101)
///       08                      # field_index(Request::deadline)
///       08                      # unsigned(8)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_request() {
    for certification_version in all_supported_versions() {
        let request: StreamMessage = Request {
            receiver: canister_test_id(1),
            sender: canister_test_id(2),
            sender_reply_callback: CallbackId::from(3),
            payment: Cycles::new(4),
            method_name: "test".to_string(),
            method_payload: vec![6],
            metadata: RequestMetadata::new(13, Time::from_nanos_since_unix_epoch(101)),
            deadline: CoarseTime::from_secs_since_unix_epoch(8),
        }
        .into();

        assert_eq!(
            "A1 00 A8 00 4A 00 00 00 00 00 00 00 01 01 01 01 4A 00 00 00 00 00 00 00 02 01 01 02 03 03 A1 00 A1 00 04 04 64 74 65 73 74 05 41 06 07 A2 00 0D 01 18 65 08 08",
            as_hex(&encode_message(&request, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Request(
///     Request {
///         receiver: canister_test_id(1),
///         sender: canister_test_id(2),
///         sender_reply_callback: CallbackId::from(3),
///         payment: Funds::new(Cycles::new(123456789012345678901234567890)),
///         method_name: "test".to_string(),
///         method_payload: vec![6],
///         metadata: Default::default(),
///         deadline: NO_DEADLINE,
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    00                         # field_index(StreamMessage::request)
///    A7                         # map(7)
///       00                      # field_index(Request::receiver)
///       4A                      # bytes(10)
///          00000000000000010101 # "\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01"
///       01                      # field_index(Request::sender)
///       4A                      # bytes(10)
///          00000000000000020101 # "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01"
///       02                      # field_index(Request::sender_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Request::payment)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A2                   # map(2)
///             00                # field_index(Cycles::low)
///             1B C373E0EE4E3F0AD2  # unsigned(14083847773837265618)
///             01                # field_index(Cycles::high)
///             1B 000000018EE09FF6  # unsigned(61672207766)
///       04                      # field_index(Request::method_name)
///       64                      # text(4)
///          74657374             # "test"
///       05                      # field_index(Request::method_payload)
///       41                      # bytes(1)
///          06                   # "\x06"
///       07                        # field_index(Request::metadata)
///       A2                        # map(2)
///          00                     # field_index(RequestMetadata::call_tree_depth)
///          00                     # unsigned(0)
///          01                     # field_index(RequestMetadata::call_tree_start_time_u64)
///          00                     # unsigned(0)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_request_with_u128_cycles() {
    for certification_version in all_supported_versions() {
        let request: StreamMessage = Request {
            receiver: canister_test_id(1),
            sender: canister_test_id(2),
            sender_reply_callback: CallbackId::from(3),
            payment: Cycles::new(123456789012345678901234567890),
            method_name: "test".to_string(),
            method_payload: vec![6],
            metadata: Default::default(),
            deadline: NO_DEADLINE,
        }
        .into();

        assert_eq!(
            "A1 00 A7 00 4A 00 00 00 00 00 00 00 01 01 01 01 4A 00 00 00 00 00 00 00 02 01 01 02 03 03 A1 00 A2 00 1B C3 73 E0 EE 4E 3F 0A D2 01 1B 00 00 00 01 8E E9 0F F6 04 64 74 65 73 74 05 41 06 07 A2 00 00 01 00",
            as_hex(&encode_message(&request, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Response(
///     Response {
///         originator: canister_test_id(5),
///         respondent: canister_test_id(4),
///         originator_reply_callback: CallbackId::from(3),
///         refund: Cycles::new(2),
///         response_payload: Payload::Data(vec![1]),
///         deadline: NO_DEADLINE,
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    01                         # field_index(StreamMessage::response)
///    A5                         # map(5)
///       00                      # field_index(Response::originator)
///       4A                      # bytes(10)
///          00000000000000050101 # "\x00\x00\x00\x00\x00\x00\x00\x06\x01\x01"
///       01                      # field_index(Response::respondent)
///       4A                      # bytes(10)
///          00000000000000040101 # "\x00\x00\x00\x00\x00\x00\x00\x05\x01\x01"
///       02                      # field_index(Response::originator_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Response::refund)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A1                   # map(1)
///             00                # field_index(Cycles::low)
///             02                # unsigned(2)
///       04                      # field_index(Response::response_payload)
///       A1                      # map(1)
///          00                   # field_index(Payload::data)
///          41                   # bytes(1)
///             01                # "\x01"
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_response_no_deadline() {
    for certification_version in all_supported_versions() {
        let response: StreamMessage = Response {
            originator: canister_test_id(5),
            respondent: canister_test_id(4),
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(2),
            response_payload: Payload::Data(vec![1]),
            deadline: NO_DEADLINE,
        }
        .into();

        assert_eq!(
            "A1 01 A5 00 4A 00 00 00 00 00 00 00 05 01 01 01 4A 00 00 00 00 00 00 00 04 01 01 02 03 03 A1 00 A1 00 02 04 A1 00 41 01",
            as_hex(&encode_message(&response, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Response(
///     Response {
///         originator: canister_test_id(5),
///         respondent: canister_test_id(4),
///         originator_reply_callback: CallbackId::from(3),
///         refund: Cycles::new(2),
///         response_payload: Payload::Data(vec![1]),
///         deadline: CoarseTime(6),
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    01                         # field_index(StreamMessage::response)
///    A6                         # map(6)
///       00                      # field_index(Response::originator)
///       4A                      # bytes(10)
///          00000000000000050101 # "\x00\x00\x00\x00\x00\x00\x00\x06\x01\x01"
///       01                      # field_index(Response::respondent)
///       4A                      # bytes(10)
///          00000000000000040101 # "\x00\x00\x00\x00\x00\x00\x00\x05\x01\x01"
///       02                      # field_index(Response::originator_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Response::refund)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A1                   # map(1)
///             00                # field_index(Cycles::low)
///             02                # unsigned(2)
///       04                      # field_index(Response::response_payload)
///       A1                      # map(1)
///          00                   # field_index(Payload::data)
///          41                   # bytes(1)
///             01                # "\x01"
///       06                      # field_index(Response::deadline)
///       06                      # unsigned(6)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_response() {
    for certification_version in all_supported_versions() {
        let response: StreamMessage = Response {
            originator: canister_test_id(5),
            respondent: canister_test_id(4),
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(2),
            response_payload: Payload::Data(vec![1]),
            deadline: CoarseTime::from_secs_since_unix_epoch(6),
        }
        .into();

        assert_eq!(
            "A1 01 A6 00 4A 00 00 00 00 00 00 00 05 01 01 01 4A 00 00 00 00 00 00 00 04 01 01 02 03 03 A1 00 A1 00 02 04 A1 00 41 01 06 06",
            as_hex(&encode_message(&response, certification_version))
        );
    }
}

///
/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Response(
///     Response {
///         originator: canister_test_id(5),
///         respondent: canister_test_id(4),
///         originator_reply_callback: CallbackId::from(3),
///         refund: Funds::new(Cycles::new(123456789012345678901234567890)),
///         response_payload: Payload::Data(vec![1]),
///         deadline: NO_DEADLINE,
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    01                         # field_index(StreamMessage::response)
///    A5                         # map(5)
///       00                      # field_index(Response::originator)
///       4A                      # bytes(10)
///          00000000000000050101 # "\x00\x00\x00\x00\x00\x00\x00\x06\x01\x01"
///       01                      # field_index(Response::respondent)
///       4A                      # bytes(10)
///          00000000000000040101 # "\x00\x00\x00\x00\x00\x00\x00\x05\x01\x01"
///       02                      # field_index(Response::originator_reply_callback)
///       03                      # unsigned(3)
///       03                      # field_index(Response::refund)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A2                   # map(2)
///             00                # field_index(Cycles::low)
///             1B C373E0EE4E3F0AD2  # unsigned(14083847773837265618)
///             01                # field_index(Cycles::high)
///             1B 000000018EE09FF6  # unsigned(61672207766)
///       04                      # field_index(Response::response_payload)
///       A1                      # map(1)
///          00                   # field_index(Payload::data)
///          41                   # bytes(1)
///             01                # "\x01"
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_response_with_u128_cycles() {
    for certification_version in all_supported_versions() {
        let response: StreamMessage = Response {
            originator: canister_test_id(5),
            respondent: canister_test_id(4),
            originator_reply_callback: CallbackId::from(3),
            refund: Cycles::new(123456789012345678901234567890),
            response_payload: Payload::Data(vec![1]),
            deadline: NO_DEADLINE,
        }
        .into();

        assert_eq!(
            "A1 01 A5 00 4A 00 00 00 00 00 00 00 05 01 01 01 4A 00 00 00 00 00 00 00 04 01 01 02 03 03 A1 00 A2 00 1B C3 73 E0 EE 4E 3F 0A D2 01 1B 00 00 00 01 8E E9 0F F6 04 A1 00 41 01",
            as_hex(&encode_message(&response, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// StreamMessage::Response(
///     Response {
///         originator: canister_test_id(6),
///         respondent: canister_test_id(5),
///         originator_reply_callback: CallbackId::from(4),
///         refund: Cycles::new(3),
///         response_payload: Payload::Reject(RejectContext {
///             code: RejectCode::SysFatal,
///             message: "Oops".into(),
///         }),
///         deadline: NO_DEADLINE,
///     }
/// )
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    01                         # field_index(StreamMessage::response)
///    A5                         # map(5)
///       00                      # field_index(Response::originator)
///       4A                      # bytes(10)
///          00000000000000060101 # "\x00\x00\x00\x00\x00\x00\x00\x06\x01\x01"
///       01                      # field_index(Response::respondent)
///       4A                      # bytes(10)
///          00000000000000050101 # "\x00\x00\x00\x00\x00\x00\x00\x05\x01\x01"
///       02                      # field_index(Response::originator_reply_callback)
///       04                      # unsigned(4)
///       03                      # field_index(Response::refund)
///       A1                      # map(1)
///          00                   # field_index(Funds::cycles)
///          A1                   # map(1)
///             00                # field_index(Cycles::low)
///             03                # unsigned(3)
///       04                      # field_index(Response::response_payload)
///       A1                      # map(1)
///          01                   # field_index(Payload::reject)
///          A2                   # map(2)
///             00                # field_index(RejectContext::code)
///             01                # unsigned(1)
///             01                # field_index(RejectContext::message)
///             64                # text(4)
///                4F6F7073       # "Oops"
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_reject_response() {
    for certification_version in all_supported_versions() {
        let reject_response: StreamMessage = Response {
            originator: canister_test_id(6),
            respondent: canister_test_id(5),
            originator_reply_callback: CallbackId::from(4),
            refund: Cycles::new(3),
            response_payload: Payload::Reject(reject_context()),
            deadline: NO_DEADLINE,
        }
        .into();

        assert_eq!(
            "A1 01 A5 00 4A 00 00 00 00 00 00 00 06 01 01 01 4A 00 00 00 00 00 00 00 05 01 01 02 04 03 A1 00 A1 00 03 04 A1 01 A2 00 01 01 64 4F 6F 70 73",
            as_hex(&encode_message(&reject_response, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// Refund {
///     recipient: canister_test_id(7),
///     amount: Cycles::new(8),
/// }
/// ```
///
/// Expected:
///
/// ```text
/// A1                            # map(1)
///    02                         # field_index(StreamMessage::refund)
///    A2                         # map(2)
///       00                      # field_index(Refund::recipient)
///       4A                      # bytes(10)
///          00000000000000070101 # "\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0007\u0001\u0001"
///       01                      # field_index(Refund::amount)
///       A1                      # map(1)
///          00                   # field_index(Cycles::low)
///          08                   # unsigned(8)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_anonymous_refund() {
    for certification_version in
        all_supported_versions().filter(|v| *v >= CertificationVersion::V22)
    {
        let refund: StreamMessage = Refund::anonymous(canister_test_id(7), Cycles::new(8)).into();

        assert_eq!(
            "A1 02 A2 00 4A 00 00 00 00 00 00 00 07 01 01 01 A1 00 08",
            as_hex(&encode_message(&refund, certification_version))
        );
    }
}

/// Canonical CBOR encoding of:
///
/// ```no_run
/// SystemMetadata {
///     own_subnet_id: new(subnet_test_id(13)),
///     prev_state_hash: Some(CryptoHashOfPartialState::new(CryptoHash(vec![15]))),
///     ..Default::default()
/// }
/// ```
///
/// Expected:
///
/// ```text
/// A2       # map(2)
///    00    # field_index(SystemMetadata::id_counter)
///    00    # unsigned(0)
///    01    # field_index(SystemMetadata::prev_state_hash)
///    81    # array(1)
///       0F # unsigned(15)
/// ```
/// Used http://cbor.me/ for printing the human friendly output.
#[test]
fn canonical_encoding_system_metadata() {
    for certification_version in all_supported_versions() {
        let mut metadata = SystemMetadata::new(subnet_test_id(13), SubnetType::Application);
        metadata.prev_state_hash = Some(CryptoHashOfPartialState::new(CryptoHash(vec![15])));

        assert_eq!(
            "A1 01 81 0F",
            as_hex(&encode_metadata(&metadata, certification_version))
        );
    }
}

//
// `StreamHeader` decoding
//

#[test]
fn valid_stream_header() {
    for certification_version in all_supported_versions() {
        let stream_header = stream_header(certification_version);
        let bytes =
            types::StreamHeader::proxy_encode((&stream_header, certification_version)).unwrap();

        let _: StreamHeader = types::StreamHeader::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "expected field index 0 <= i < 6")]
fn invalid_stream_header_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamHeader::encode_with_extra_field((
            &stream_header(certification_version),
            certification_version,
        ))
        .unwrap();

        let _: StreamHeader = types::StreamHeader::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `begin`")]
fn invalid_stream_header_missing_begin() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamHeader::encode_without_field(
            (&stream_header(certification_version), certification_version),
            0,
        )
        .unwrap();

        let _: StreamHeader = types::StreamHeader::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `end`")]
fn invalid_stream_header_missing_end() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamHeader::encode_without_field(
            (&stream_header(certification_version), certification_version),
            1,
        )
        .unwrap();

        let _: StreamHeader = types::StreamHeader::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `signals_end`")]
fn invalid_stream_header_missing_signals_end() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamHeader::encode_without_field(
            (&stream_header(certification_version), certification_version),
            2,
        )
        .unwrap();

        let _: StreamHeader = types::StreamHeader::proxy_decode(&bytes).unwrap();
    }
}

//
// `StreamMessage` decoding
//

#[test]
#[should_panic(expected = "expected field index 0 <= i < 3")]
fn invalid_message_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamMessage::encode_with_extra_field((
            &request_message(certification_version),
            certification_version,
        ))
        .unwrap();

        let _: StreamMessage = types::StreamMessage::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(
    expected = "StreamMessage: expected exactly one of `request`, `response` or `refund` to be `Some(_)`, got `StreamMessage { request: None, response: None, refund: None }`"
)]
fn invalid_message_empty() {
    for certification_version in all_supported_versions() {
        let bytes = types::StreamMessage::encode_without_field(
            (
                &request_message(certification_version),
                certification_version,
            ),
            0,
        )
        .unwrap();

        let _: StreamMessage = types::StreamMessage::proxy_decode(&bytes).unwrap();
    }
}

//
// `Request` decoding
//

#[test]
fn valid_request() {
    for certification_version in all_supported_versions() {
        let request = request(certification_version);
        let bytes = types::Request::proxy_encode((&request, certification_version)).unwrap();

        assert_eq!(request, types::Request::proxy_decode(&bytes).unwrap());
    }
}

#[test]
fn invalid_request_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_with_extra_field((
            &request(certification_version),
            certification_version,
        ))
        .unwrap();

        let res: Result<Request, ProxyDecodeError> = types::Request::proxy_decode(&bytes);
        assert_matches!(
            res,
            Err(ProxyDecodeError::CborDecodeError(err))
                if err.to_string().contains("expected field index 0 <= i < 9")
        );
    }
}

#[test]
#[should_panic(expected = "missing field `receiver`")]
fn invalid_request_missing_receiver() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            0,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `sender`")]
fn invalid_request_missing_sender() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            1,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `sender_reply_callback`")]
fn invalid_request_missing_sender_reply_callback() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            2,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `payment`")]
fn invalid_request_missing_payment() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            3,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `method_name`")]
fn invalid_request_missing_method_name() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            4,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `method_payload`")]
fn invalid_request_missing_method_payload() {
    for certification_version in all_supported_versions() {
        let bytes = types::Request::encode_without_field(
            (&request(certification_version), certification_version),
            5,
        )
        .unwrap();

        let _: Request = types::Request::proxy_decode(&bytes).unwrap();
    }
}

//
// `Response` decoding
//

#[test]
fn valid_response() {
    for certification_version in all_supported_versions() {
        let response = response(certification_version);
        let bytes = types::Response::proxy_encode((&response, certification_version)).unwrap();

        assert_eq!(response, types::Response::proxy_decode(&bytes).unwrap());
    }
}

#[test]
fn invalid_response_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_with_extra_field((
            &response(certification_version),
            certification_version,
        ))
        .unwrap();

        let res: Result<Response, ProxyDecodeError> = types::Response::proxy_decode(&bytes);
        assert_matches!(
            res,
            Err(ProxyDecodeError::CborDecodeError(err))
                if err.to_string().contains("expected field index 0 <= i < 7")
        );
    }
}

#[test]
#[should_panic(expected = "missing field `originator`")]
fn invalid_response_missing_originator() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_without_field(
            (&response(certification_version), certification_version),
            0,
        )
        .unwrap();

        let _: Response = types::Response::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `respondent`")]
fn invalid_response_missing_respondent() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_without_field(
            (&response(certification_version), certification_version),
            1,
        )
        .unwrap();

        let _: Response = types::Response::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `originator_reply_callback`")]
fn invalid_response_missing_originator_reply_callback() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_without_field(
            (&response(certification_version), certification_version),
            2,
        )
        .unwrap();

        let _: Response = types::Response::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `refund`")]
fn invalid_response_missing_refund() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_without_field(
            (&response(certification_version), certification_version),
            3,
        )
        .unwrap();

        let _: Response = types::Response::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `response_payload`")]
fn invalid_response_missing_response_payload() {
    for certification_version in all_supported_versions() {
        let bytes = types::Response::encode_without_field(
            (&response(certification_version), certification_version),
            4,
        )
        .unwrap();

        let _: Response = types::Response::proxy_decode(&bytes).unwrap();
    }
}

//
// `Refund` decoding
//

#[test]
fn valid_anonymous_refund() {
    for certification_version in
        all_supported_versions().filter(|v| *v >= CertificationVersion::V22)
    {
        let refund = anonymous_refund(certification_version);
        let bytes = types::Refund::proxy_encode((&refund, certification_version)).unwrap();

        assert_eq!(refund, types::Refund::proxy_decode(&bytes).unwrap());
    }
}

#[test]
fn invalid_refund_extra_field() {
    for certification_version in
        all_supported_versions().filter(|v| *v >= CertificationVersion::V22)
    {
        let bytes = types::Refund::encode_with_extra_field((
            &anonymous_refund(certification_version),
            certification_version,
        ))
        .unwrap();

        let res: Result<Refund, ProxyDecodeError> = types::Refund::proxy_decode(&bytes);
        assert_matches!(
            res,
            Err(ProxyDecodeError::CborDecodeError(err))
                if err.to_string().contains("expected field index 0 <= i < 2")
        );
    }
}

#[test]
#[should_panic(expected = "missing field `recipient`")]
fn invalid_refund_missing_recipient() {
    for certification_version in
        all_supported_versions().filter(|v| *v >= CertificationVersion::V22)
    {
        let bytes = types::Refund::encode_without_field(
            (
                &anonymous_refund(certification_version),
                certification_version,
            ),
            0,
        )
        .unwrap();

        let _: Refund = types::Refund::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `amount`")]
fn invalid_refund_missing_amount() {
    for certification_version in
        all_supported_versions().filter(|v| *v >= CertificationVersion::V22)
    {
        let bytes = types::Refund::encode_without_field(
            (
                &anonymous_refund(certification_version),
                certification_version,
            ),
            1,
        )
        .unwrap();

        let _: Refund = types::Refund::proxy_decode(&bytes).unwrap();
    }
}

//
// `Funds` decoding
//

#[test]
fn valid_funds() {
    for certification_version in all_supported_versions() {
        let funds = funds();
        let bytes = types::Funds::proxy_encode((&funds, certification_version)).unwrap();

        assert_eq!(funds, types::Funds::proxy_decode(&bytes).unwrap());
    }
}

#[test]
#[should_panic(expected = "expected field index 0 <= i < 2")]
fn invalid_funds_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes =
            types::Funds::encode_with_extra_field((&funds(), certification_version)).unwrap();

        let _: Funds = types::Funds::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `cycles`")]
fn invalid_funds_missing_cycles() {
    for certification_version in all_supported_versions() {
        let bytes =
            types::Funds::encode_without_field((&funds(), certification_version), 0).unwrap();

        let _: Funds = types::Funds::proxy_decode(&bytes).unwrap();
    }
}

//
// `Payload` decoding
//

#[test]
fn valid_data_payload() {
    for certification_version in all_supported_versions() {
        let payload = data_payload();
        let bytes = types::Payload::proxy_encode((&payload, certification_version)).unwrap();

        assert_eq!(payload, types::Payload::proxy_decode(&bytes).unwrap());
    }
}

#[test]
fn valid_reject_payload() {
    for certification_version in all_supported_versions() {
        let payload = reject_payload();
        let bytes = types::Payload::proxy_encode((&payload, certification_version)).unwrap();

        assert_eq!(payload, types::Payload::proxy_decode(&bytes).unwrap());
    }
}

#[test]
#[should_panic(expected = "expected field index 0 <= i < 2")]
fn invalid_payload_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes =
            types::Payload::encode_with_extra_field((&data_payload(), certification_version))
                .unwrap();

        let _: Payload = types::Payload::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(
    expected = "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `Payload { data: None, reject: None }`"
)]
fn invalid_payload_empty() {
    for certification_version in all_supported_versions() {
        let bytes =
            types::Payload::encode_without_field((&data_payload(), certification_version), 0)
                .unwrap();

        let _: Payload = types::Payload::proxy_decode(&bytes).unwrap();
    }
}

//
// `RejectContext` decoding
//

#[test]
fn valid_reject_context() {
    for certification_version in all_supported_versions() {
        let context = reject_context();
        let bytes = types::RejectContext::proxy_encode((&context, certification_version)).unwrap();

        assert_eq!(context, types::RejectContext::proxy_decode(&bytes).unwrap());
    }
}

#[test]
#[should_panic(expected = "expected field index 0 <= i < 2")]
fn invalid_reject_context_extra_field() {
    for certification_version in all_supported_versions() {
        let bytes = types::RejectContext::encode_with_extra_field((
            &reject_context(),
            certification_version,
        ))
        .unwrap();

        let _: RejectContext = types::RejectContext::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `code`")]
fn invalid_reject_context_missing_code() {
    for certification_version in all_supported_versions() {
        let bytes = types::RejectContext::encode_without_field(
            (&reject_context(), certification_version),
            0,
        )
        .unwrap();

        let _: RejectContext = types::RejectContext::proxy_decode(&bytes).unwrap();
    }
}

#[test]
#[should_panic(expected = "missing field `message`")]
fn invalid_reject_context_missing_message() {
    for certification_version in all_supported_versions() {
        let bytes = types::RejectContext::encode_without_field(
            (&reject_context(), certification_version),
            1,
        )
        .unwrap();

        let _: RejectContext = types::RejectContext::proxy_decode(&bytes).unwrap();
    }
}

/// Converts a blob into a hex representation that can be pasted into http://cbor.me
pub fn as_hex(buf: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    if buf.is_empty() {
        return "".into();
    }

    let mut res = String::with_capacity(3 * buf.len());
    for b in buf {
        res.push(DIGITS[*b as usize >> 4] as char);
        res.push(DIGITS[*b as usize & 0xF] as char);
        res.push(' ');
    }
    res.pop();
    res
}

/// A proxy encoder that allows adding and removing fields in the encoded
/// message, as helper for decoding tests.
pub trait TestingProxyEncoder<T> {
    /// Encodes `t` into a vector, adding an extra field.
    fn encode_with_extra_field(t: T) -> Result<Vec<u8>, serde_cbor::Error>;

    /// Encodes `t` into a vector, removing the field with the given index.
    fn encode_without_field(t: T, field: usize) -> Result<Vec<u8>, serde_cbor::Error>;
}

impl<T, M> TestingProxyEncoder<T> for M
where
    T: Into<M> + std::fmt::Debug,
    M: serde::Serialize,
{
    fn encode_with_extra_field(t: T) -> Result<Vec<u8>, serde_cbor::Error> {
        let add_field = |mut map: MapValue| {
            let prev = map.insert(Value::Integer(999), Value::Integer(999));
            assert!(
                prev.is_none(),
                "Expected no field with index 999, found {prev:?}"
            );
            map
        };

        encode_with_mutation(&t.into(), &add_field)
    }

    fn encode_without_field(t: T, field: usize) -> Result<Vec<u8>, serde_cbor::Error> {
        let remove_field = |mut map: MapValue| {
            map.remove(&Value::Integer(field as i128))
                .unwrap_or_else(|| panic!("No such field: {field}"));
            map
        };

        encode_with_mutation(&t.into(), &remove_field)
    }
}

type MapValue = BTreeMap<Value, Value>;

fn encode_with_mutation<T: serde::Serialize>(
    t: &T,
    mutate: &dyn Fn(MapValue) -> MapValue,
) -> Result<Vec<u8>, serde_cbor::Error> {
    let bytes = serde_cbor::ser::to_vec_packed(t)?;
    let value: Value = serde_cbor::de::from_slice(&bytes)?;

    let value = match value {
        Value::Map(map) => Value::Map(mutate(map)),
        other => panic!("Expected struct to serialize to a map, was {other:?}"),
    };

    serde_cbor::ser::to_vec_packed(&value)
}

//
// Own fixtures, to ensure that compatibility tests are self-contained.
//

fn stream_header(certification_version: CertificationVersion) -> StreamHeader {
    let (reject_signals, signals_end) = reject_signals(certification_version);
    StreamHeader::new(
        23.into(),
        25.into(),
        signals_end,
        reject_signals,
        StreamFlags {
            deprecated_responses_only: true,
        },
    )
}

fn reject_signals(
    _certification_version: CertificationVersion,
) -> (VecDeque<RejectSignal>, StreamIndex) {
    (
        vec![
            RejectSignal::new(RejectReason::CanisterMigrating, 249.into()),
            RejectSignal::new(RejectReason::CanisterNotFound, 250.into()),
            RejectSignal::new(RejectReason::CanisterStopped, 251.into()),
            RejectSignal::new(RejectReason::CanisterStopping, 252.into()),
            RejectSignal::new(RejectReason::QueueFull, 253.into()),
            RejectSignal::new(RejectReason::OutOfMemory, 254.into()),
            RejectSignal::new(RejectReason::Unknown, 255.into()),
        ]
        .into(),
        256.into(),
    )
}

fn request_message(certification_version: CertificationVersion) -> StreamMessage {
    request(certification_version).into()
}

fn request(_certification_version: CertificationVersion) -> Request {
    Request {
        receiver: canister_test_id(1),
        sender: canister_test_id(2),
        sender_reply_callback: CallbackId::from(3),
        payment: cycles(),
        method_name: "test".to_string(),
        method_payload: vec![6],
        metadata: request_metadata(),
        deadline: CoarseTime::from_secs_since_unix_epoch(8),
    }
}

fn response(_certification_version: CertificationVersion) -> Response {
    Response {
        originator: canister_test_id(6),
        respondent: canister_test_id(5),
        originator_reply_callback: CallbackId::from(4),
        refund: cycles(),
        response_payload: data_payload(),
        deadline: CoarseTime::from_secs_since_unix_epoch(8),
    }
}

fn anonymous_refund(_certification_version: CertificationVersion) -> Refund {
    Refund::anonymous(canister_test_id(7), cycles())
}

fn funds() -> Funds {
    Funds::new(Cycles::new(3))
}

fn cycles() -> Cycles {
    Cycles::new(3)
}

fn data_payload() -> Payload {
    Payload::Data(vec![1])
}

fn reject_payload() -> Payload {
    Payload::Reject(reject_context())
}

fn reject_context() -> RejectContext {
    RejectContext::new(RejectCode::SysFatal, "Oops")
}

fn request_metadata() -> RequestMetadata {
    RequestMetadata::new(13, Time::from_nanos_since_unix_epoch(101))
}
