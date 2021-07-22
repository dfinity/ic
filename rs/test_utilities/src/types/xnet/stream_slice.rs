use crate::types::messages::RequestBuilder;
use ic_types::{
    messages::{Request, RequestOrResponse},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue, StreamSlice},
    CanisterId,
};

pub struct StreamSliceBuilder {
    messages: StreamIndexedQueue<RequestOrResponse>,
    header: StreamHeader,
}

impl Default for StreamSliceBuilder {
    /// Creates a dummy Stream with default values.
    fn default() -> Self {
        let header_builder = super::stream_header::StreamHeaderBuilder::default();
        Self {
            messages: StreamIndexedQueue::default(),
            header: header_builder.build(),
        }
    }
}

impl StreamSliceBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the messages in the stream.
    pub fn messages(mut self, messages: StreamIndexedQueue<RequestOrResponse>) -> Self {
        self.messages = messages;
        self
    }

    /// Sets the stream messages to the provided ones, starting at the given
    /// index.
    pub fn with_messages(mut self, begin: StreamIndex, msgs: Vec<Request>) -> Self {
        self.messages = StreamIndexedQueue::with_begin(begin);
        for msg in msgs {
            self.messages.push(msg.into());
        }
        self
    }

    /// Generates a range of `Request` messages from the given sender to the
    /// given receiver, starting at the given index.
    pub fn generate_messages(
        mut self,
        begin: StreamIndex,
        count: u64,
        sender: CanisterId,
        receiver: CanisterId,
    ) -> Self {
        self.messages = StreamIndexedQueue::with_begin(begin);
        for x in 0..count {
            self.messages.push(
                RequestBuilder::new()
                    .sender(sender)
                    .receiver(receiver)
                    // differentiate the messages
                    .method_name(format!("request_{}", begin + StreamIndex::from(x)))
                    .build()
                    .into(),
            );
        }
        self
    }

    /// Sets the header for the stream.
    pub fn header(mut self, header: StreamHeader) -> Self {
        self.header = header;
        self
    }

    /// Returns the built StreamSlice.
    pub fn build(self) -> StreamSlice {
        StreamSlice::new(self.header, self.messages)
    }
}
