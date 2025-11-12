use candid::{CandidType, Decode, Encode, Principal};
use serde::{Deserialize, Serialize};

/// Includes all the information for a call to this canister.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, CandidType)]
pub struct Call {
    /// The receiver canister of this call.
    pub receiver: Principal,
    /// The number of bytes the payload of the message sent to the `receiver` should have.
    pub call_bytes: u32,
    /// The number of bytes the payload received in the reply from the `receiver` should have.
    pub reply_bytes: u32,
    /// The amount of cycles to send with the call.
    pub cycles: u128,
    /// The timeout used for a best effort call; `Some(_)`: best effort call, `None`: guaranteed response call.
    pub timeout_secs: Option<u32>,
    /// A list of downstream calls `receiver` should attempt.
    pub downstream_calls: Vec<Call>,
}

impl Default for Call {
    fn default() -> Self {
        // Default with a dummy canister ID and no padding or downstream calls.
        Self {
            receiver: Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap(),
            call_bytes: 0,
            reply_bytes: 0,
            cycles: 0,
            timeout_secs: None,
            downstream_calls: vec![],
        }
    }
}

/// Override `Debug` to pretty-print receivers. `Principal` implements `Display`
/// but derives `Debug`.
impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call")
            .field("receiver", &self.receiver.to_text())
            .field("call_bytes", &self.call_bytes)
            .field("reply_bytes", &self.reply_bytes)
            .field("cycles", &self.cycles)
            .field("timeout_secs", &self.timeout_secs)
            .field("downstream_calls_count", &self.downstream_calls.len())
            .finish()
    }
}

/// The message sent to this canister by an ingress or an inter canister message.
#[derive(Serialize, Deserialize, CandidType, Debug, Eq, PartialEq)]
pub struct CallMessage {
    /// The call index for this call, i.e. a strictly increasing integer (with each call).
    pub call_index: u32,
    /// The number of bytes the reply to this call should have.
    pub reply_bytes: u32,
    /// A list of downstream calls this call is supposed to attempt.
    pub downstream_calls: Vec<Call>,
}

/// Includes all the information for a reply from this canister.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, CandidType)]
pub enum Reply {
    /// The call to `respondent` was successful.
    Success {
        respondent: Principal,
        bytes_received_on_call: u32,
        bytes_sent_on_reply: u32,
        downstream_replies: Vec<Reply>,
    },
    /// A synchronous reject occurred, i.e. perform call failed.
    SyncReject { call: Call },
    /// An asynchronous reject occurred, e.g. queue full.
    AsyncReject {
        call: Call,
        reject_code: u32,
        reject_message: String,
    },
}

impl Reply {
    /// Traverses the `Reply` and its downstream replies recursively,
    /// depth first and calls `f` on each `Reply` and call depth.
    pub fn for_each_depth_first<F>(&self, f: &F)
    where
        F: Fn(&Self, usize),
    {
        fn traverse<F>(reply: &Reply, call_depth: usize, f: &F)
        where
            F: Fn(&Reply, usize),
        {
            f(reply, call_depth);
            if let Reply::Success {
                downstream_replies, ..
            } = reply
            {
                for reply in downstream_replies.iter() {
                    traverse(reply, call_depth + 1, f);
                }
            }
        }

        traverse(self, 0, &f);
    }
}

/// The reply message received from this canister to an ingress or an inter canister message.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, CandidType)]
pub struct ReplyMessage {
    pub bytes_received_on_call: u32,
    pub downstream_replies: Vec<Reply>,
}

/// Encodes a message of type `T` using Candid and appropriate padding
/// to result in a blob of exactly `target_bytes_count` bytes if possible.
///
/// Returns the encoded blob and the bytes count of the contained candid
/// encoded payload.
pub fn encode<T>(msg: &T, target_bytes_count: usize) -> (Vec<u8>, u32)
where
    T: Serialize + for<'a> Deserialize<'a> + CandidType,
{
    // Encode `msg` in Candid as usual.
    let mut payload = candid::Encode!(msg).expect("candid encoding failed");
    let payload_size_bytes = payload.len();

    // Create bytes vector [payload.len(); payload; padding].
    let capacity = std::cmp::max(target_bytes_count, payload.len() + 4);
    let mut bytes = Vec::with_capacity(capacity);

    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.append(&mut payload);
    bytes.resize(capacity, 13_u8);

    (bytes, payload_size_bytes as u32)
}

/// Decodes a blob into a type `T`, discarding any possible padding.
///
/// Returns the decoded type `T`, the bytes count of the blob and the
/// bytes count of the contained candid encoded payload.
pub fn decode<T>(blob: Vec<u8>) -> (T, u32, u32)
where
    T: Serialize + for<'a> Deserialize<'a> + CandidType,
{
    let blob_bytes_count = blob.len() as u32;
    let payload_bytes_count = u32::from_le_bytes(<[u8; 4]>::try_from(&blob[0..4]).unwrap());
    (
        candid::Decode!(&blob[4..(4 + payload_bytes_count as usize)], T).unwrap(),
        blob_bytes_count,
        payload_bytes_count,
    )
}

// Enable Candid export.
ic_cdk::export_candid!();
