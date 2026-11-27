tonic::include_proto!("https_outcalls_service.v1");

/// The largest message either side of the HTTPS outcalls service decodes: a request or
/// response of up to 4 MB of headers and body, plus its URL and the message framing.
pub const MAX_MESSAGE_SIZE_BYTES: usize = 5 * 1024 * 1024;
