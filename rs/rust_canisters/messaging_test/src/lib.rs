use candid::{CandidType, Decode, Encode};
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};

/// Includes all the information for a call to this canister.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, CandidType)]
pub struct Call {
    /// The receiver canister of this call.
    pub receiver: CanisterId,
    /// The number of bytes the payload of the message sent to the `receiver` should have.
    pub call_bytes: u32,
    /// The number of bytes the payload received in the reply from the `receiver` should have.
    pub reply_bytes: u32,
    /// The timeout used for a best effort call; `Some(_)`: best effort call, `None`: guaranteed response call.
    pub timeout_secs: Option<u32>,
    /// A list of downstream calls `receiver` should attempt.
    pub downstream_calls: Vec<Call>,
}

/// The message sent to this canister by an ingress or an inter canister message.
#[derive(Serialize, Deserialize, CandidType)]
pub struct Message {
    /// The call index for this call, i.e. a strictly increasing integer (with each call).
    pub call_index: u32,
    /// The number of bytes the reply to this call should have.
    pub reply_bytes: u32,
    /// A list of downstream calls this call is supposed to attempt.
    pub downstream_calls: Vec<Call>,
}

/// A `Message` encoded with Candid and some padding to reach a target payload size.
#[derive(Serialize, Deserialize, CandidType)]
struct MessageWithPadding {
    #[serde(with = "serde_bytes")]
    message: Vec<u8>,
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

/// Reply type (Reply, padding)
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, CandidType)]
pub enum Response {
    /// The call to `respondent` was successful.
    Success {
        bytes_received: u32,
        bytes_sent_back: u32,
        downstream_responses: Vec<(CanisterId, Response)>,
    },
    /// A synchronous reject occurred, i.e. perform call failed.
    SyncReject,
    /// An asynchronous reject occurred, e.g. queue full.
    AsyncReject {
        reject_code: u32,
        reject_message: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, CandidType)]
pub struct Reply {
    pub downstream_responses: Vec<(CanisterId, Response)>,
}

/// A `Reply` encoded with Candid and some padding to reach a target payload size.
#[derive(Serialize, Deserialize, CandidType)]
struct ReplyWithPadding {
    #[serde(with = "serde_bytes")]
    reply: Vec<u8>,
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

/// Encodes a `Message` such that the resulting blob has a target size.
pub fn encode_message(msg: &Message, target_bytes_count: usize) -> Vec<u8> {
    let message = candid::Encode!(msg).expect("encoding message failed");
    let padding = vec![13_u8; target_bytes_count.saturating_sub(message.len())];
    let result = candid::Encode!(&MessageWithPadding { message, padding })
        .expect("encoding with padding failed");
    assert_eq!(result.len(), target_bytes_count);
    result
}

/// Decodes a `Message` extended with a padding; ignores the padding and returns the decoded `Message`.
pub fn decode_message(blob: Vec<u8>) -> (Message, u32) {
    let bytes_count = blob.len() as u32;
    let MessageWithPadding { message, .. } = candid::Decode!(blob.as_slice(), MessageWithPadding)
        .expect("failed to decode message with padding");
    (
        candid::Decode!(message.as_slice(), Message).expect("failed to decode Message"),
        bytes_count,
    )
}

/// Encodes a `Reply` such that the resulting blob has a target size.
pub fn encode_reply(
    downstream_responses: Vec<(CanisterId, Response)>,
    target_bytes_count: usize,
) -> Vec<u8> {
    let reply = candid::Encode!(&Reply {
        downstream_responses
    })
    .expect("encoding reply with padding failed");
    let padding = vec![17_u8; target_bytes_count.saturating_sub(reply.len())];

    candid::Encode!(&ReplyWithPadding { reply, padding }).expect("failed to encode reply")
}

/// Decodes a `Reply`, ignoring the padding.
pub fn decode_reply(blob: Vec<u8>) -> Reply {
    let ReplyWithPadding { reply, .. } = candid::Decode!(blob.as_slice(), ReplyWithPadding)
        .expect("failed to decode reply with padding");
    candid::Decode!(reply.as_slice(), Reply).expect("failed to decode reply")
}

// Enable Candid export.
ic_cdk::export_candid!();
