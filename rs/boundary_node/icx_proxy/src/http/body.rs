use crate::error::ErrorFactory;
use http_body::{LengthLimitError, Limited};
use hyper::{body, Body};

/// Read the body from the available stream enforcing a size limit.
pub async fn read_streaming_body(
    body_stream: Body,
    size_limit: usize,
) -> Result<Vec<u8>, ErrorFactory> {
    let limited_body = Limited::new(body_stream, size_limit);

    match body::to_bytes(limited_body).await {
        Ok(data) => Ok(data.to_vec()),
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return Err(ErrorFactory::PayloadTooLarge);
            }
            Err(ErrorFactory::BodyReadFailed(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorFactory;
    use crate::http::body::read_streaming_body;
    use hyper::Body;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn body_payload_too_large() {
        let result: Result<Vec<u8>, ErrorFactory> = aw!(read_streaming_body(Body::from("test"), 1));

        assert!(result.is_err());
    }

    #[test]
    fn body_payload_with_accepted_size() {
        let result: Result<Vec<u8>, ErrorFactory> = aw!(read_streaming_body(Body::from("test"), 4));

        assert!(result.is_ok());
    }
}
