use prost::Message;

use crate::state::queues::v1::{request_or_response::R, *};
use crate::types::v1::{CanisterId, PrincipalId};

/// Tests that `prost` can correctly encode and then decode a protobuf of over 2 GB.
#[test]
fn huge_proto_encoding_roundtrip() {
    fn canister_id(raw: &[u8]) -> CanisterId {
        CanisterId {
            principal_id: Some(PrincipalId { raw: raw.into() }),
        }
    }

    let cycles = Cycles {
        raw_cycles: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    // A request with a 2 MB payload.
    let msg = RequestOrResponse {
        r: Some(R::Request(Request {
            receiver: Some(canister_id(&[1, 2, 3])),
            sender: Some(canister_id(&[4, 5, 6])),
            sender_reply_callback: 13,
            payment: Some(Funds {
                icp: 0,
                cycles_struct: Some(cycles.clone()),
            }),
            method_name: "do_update".into(),
            method_payload: vec![169; 2 << 20],
            cycles_payment: Some(cycles),
            metadata: None,
            deadline_seconds: 0,
        })),
    };
    // A queue of 2K requests with 2 MB payloads.
    let queue = vec![msg; 2 << 10];

    let q = InputOutputQueue {
        queue,
        begin: 2197,
        capacity: 500,
        num_slots_reserved: 14,
        deadline_range_ends: Vec::new(),
        timeout_index: 15,
    };

    let mut buf = vec![];
    q.encode(&mut buf).unwrap();
    // Expecting the encoded queue to be larger than 4 GB.
    assert!(buf.len() > 4 << 30);

    let decoded_q = InputOutputQueue::decode(buf.as_slice()).unwrap();

    // Ensure that decoding results in the same queue that we just encoded.
    assert_eq!(q, decoded_q);
}
