use ic_btc_types_internal::{
    BitcoinAdapterRequest, BitcoinAdapterRequestWrapper, BitcoinAdapterResponse,
};
use ic_protobuf::{
    bitcoin::v1 as pb_bitcoin,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::TryFrom,
};

/// Maximum number of requests to Bitcoin Adapter that can be present in the queue.
const REQUEST_QUEUE_CAPACITY: u32 = 500;

/// Errors that can be returned when handling the `BitcoinState`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BitcoinStateError {
    /// Bitcoin testnet feature not enabled.
    TestnetFeatureNotEnabled,
    /// No corresponding request found when trying to push a response.
    NonMatchingResponse { callback_id: u64 },
    /// Enqueueing a request failed due to full queue to the Bitcoin adapter.
    QueueFull { capacity: u32 },
}

impl std::error::Error for BitcoinStateError {}

impl std::fmt::Display for BitcoinStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinStateError::TestnetFeatureNotEnabled => {
                write!(f, "Bitcoin testnet feature not enabled.")
            }
            BitcoinStateError::NonMatchingResponse { callback_id } => {
                write!(
                    f,
                    "Attempted to push a response for callback id {} without an in-flight corresponding request",
                    callback_id
                )
            }
            BitcoinStateError::QueueFull { capacity } => {
                write!(
                    f,
                    "Request can not be enqueued because the queue has reached its capacity of {}.",
                    capacity
                )
            }
        }
    }
}

/// Represents the queues for requests to and responses from the Bitcoin Adapter.
/// See `ic_protobuf::bitcoin::v1` for documentation of the fields.
#[derive(Clone, Debug, PartialEq)]
struct AdapterQueues {
    next_callback_id: u64,
    requests: BTreeMap<u64, BitcoinAdapterRequest>,
    responses: VecDeque<BitcoinAdapterResponse>,
    requests_queue_capacity: u32,
    in_flight_get_successors_requests_num: u32,
}

/// Represents the bitcoin state of the subnet.
/// See `ic_protobuf::bitcoin::v1` for documentation of the fields.
#[derive(Clone, Debug, PartialEq)]
pub struct BitcoinState {
    adapter_queues: AdapterQueues,
}

impl Default for BitcoinState {
    fn default() -> Self {
        Self::new(REQUEST_QUEUE_CAPACITY)
    }
}

impl BitcoinState {
    pub fn new(requests_queue_capacity: u32) -> Self {
        Self {
            adapter_queues: AdapterQueues {
                next_callback_id: 0,
                requests: BTreeMap::new(),
                responses: VecDeque::new(),
                requests_queue_capacity,
                in_flight_get_successors_requests_num: 0,
            },
        }
    }

    /// Pushes a `BitcoinAdapterRequestWrapper` to the `BitcoinState`.
    ///
    /// Returns a `BitcoinStateError` if there's no room left in the queue for new requests.
    pub(crate) fn push_request(
        &mut self,
        request: BitcoinAdapterRequestWrapper,
    ) -> Result<(), BitcoinStateError> {
        if self.adapter_queues.requests.len() as u32 >= self.adapter_queues.requests_queue_capacity
        {
            return Err(BitcoinStateError::QueueFull {
                capacity: self.adapter_queues.requests_queue_capacity,
            });
        }

        if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) = request {
            self.adapter_queues.in_flight_get_successors_requests_num += 1;
        }
        self.adapter_queues.requests.insert(
            self.adapter_queues.next_callback_id,
            BitcoinAdapterRequest {
                request,
                callback_id: self.adapter_queues.next_callback_id,
            },
        );
        self.adapter_queues.next_callback_id += 1;
        Ok(())
    }

    /// Returns true iff there's at least an in-flight `GetSuccessorsRequest`.
    pub fn has_in_flight_get_successors_requests(&self) -> bool {
        self.adapter_queues.in_flight_get_successors_requests_num > 0
    }

    /// Returns an iterator over the existing requests to the Bitcoin Adapter.
    pub fn adapter_requests_iter(
        &self,
    ) -> std::collections::btree_map::Iter<'_, u64, BitcoinAdapterRequest> {
        self.adapter_queues.requests.iter()
    }

    /// Pushes a `BitcoinAdapterResponse` onto the `BitcoinState`. It also clears
    /// the in-flight request that corresponds to this response.
    ///
    /// Returns a `BitcoinStateError::NonMatchingResponse` error if there is no
    /// corresponding in-flight request when the response is pushed.
    pub(crate) fn push_response(
        &mut self,
        response: BitcoinAdapterResponse,
    ) -> Result<(), BitcoinStateError> {
        match self.adapter_queues.requests.remove(&response.callback_id) {
            None => Err(BitcoinStateError::NonMatchingResponse {
                callback_id: response.callback_id,
            }),
            Some(r) => {
                if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) = r.request {
                    self.adapter_queues.in_flight_get_successors_requests_num -= 1;
                }
                self.adapter_queues.responses.push_back(response);
                Ok(())
            }
        }
    }

    /// Pops the next `BitcoinAdapterResponse` from the `BitcoinState`.
    pub fn pop_response(&mut self) -> Option<BitcoinAdapterResponse> {
        self.adapter_queues.responses.pop_front()
    }

    /// Returns the number of requests to the Bitcoin Adapter.
    pub fn num_adapter_requests(&self) -> usize {
        self.adapter_queues.requests.len()
    }

    /// Returns the number of responses from the Bitcoin Adapter.
    pub fn num_adapter_responses(&self) -> usize {
        self.adapter_queues.responses.len()
    }
}

impl From<&AdapterQueues> for pb_bitcoin::AdapterQueues {
    fn from(queues: &AdapterQueues) -> pb_bitcoin::AdapterQueues {
        pb_bitcoin::AdapterQueues {
            next_callback_id: queues.next_callback_id,
            requests: queues.requests.iter().map(|(_, v)| v.into()).collect(),
            responses: queues.responses.iter().map(|x| x.into()).collect(),
            requests_queue_capacity: queues.requests_queue_capacity,
        }
    }
}

impl TryFrom<pb_bitcoin::AdapterQueues> for AdapterQueues {
    type Error = ProxyDecodeError;

    fn try_from(queues: pb_bitcoin::AdapterQueues) -> Result<Self, Self::Error> {
        let mut requests = BTreeMap::new();
        let mut in_flight_get_successors_requests_num = 0;
        for r in queues.requests.into_iter() {
            let bitcoin_adapter_request = BitcoinAdapterRequest::try_from(r)?;
            if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) =
                bitcoin_adapter_request.request
            {
                in_flight_get_successors_requests_num += 1;
            }
            requests.insert(bitcoin_adapter_request.callback_id, bitcoin_adapter_request);
        }

        let mut responses = VecDeque::new();
        for r in queues.responses.into_iter() {
            responses.push_back(BitcoinAdapterResponse::try_from(r)?);
        }

        Ok(AdapterQueues {
            next_callback_id: queues.next_callback_id,
            requests,
            responses,
            requests_queue_capacity: queues.requests_queue_capacity,
            in_flight_get_successors_requests_num,
        })
    }
}

impl From<&BitcoinState> for pb_bitcoin::BitcoinState {
    fn from(bitcoin_state: &BitcoinState) -> pb_bitcoin::BitcoinState {
        pb_bitcoin::BitcoinState {
            adapter_queues: Some((&bitcoin_state.adapter_queues).into()),
        }
    }
}

impl TryFrom<pb_bitcoin::BitcoinState> for BitcoinState {
    type Error = ProxyDecodeError;

    fn try_from(bitcoin_state: pb_bitcoin::BitcoinState) -> Result<Self, Self::Error> {
        let adapter_queues: AdapterQueues =
            try_from_option_field(bitcoin_state.adapter_queues, "BitcoinState::adapter_queues")?;
        Ok(BitcoinState { adapter_queues })
    }
}

#[cfg(test)]
mod tests;
