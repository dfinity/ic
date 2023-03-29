use crate::http::headers::IC_CERTIFICATE_HEADER_NAME;
use futures::StreamExt;
use hyper::Body;
use ic_agent::Agent;
use ic_response_verification::types::Response;
use ic_utils::{
    call::SyncCall,
    interfaces::http_request::{
        HttpRequestCanister, HttpRequestStreamingCallbackAny, HttpResponse as AgentResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    },
};
use tracing::warn;

// Limit the total number of calls to an HTTP Request loop to 1000 for now.
static MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT: usize = 1000;

// Limit the number of Stream Callbacks buffered
static STREAM_CALLBACK_BUFFER: usize = 2;

pub type AgentResponseAny = AgentResponse<Token, HttpRequestStreamingCallbackAny>;

pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Set if the body is being sent using a stream
    pub streaming_body: Option<Body>,
    pub has_streaming_body: bool,
}

impl From<(&Agent, AgentResponseAny)> for HttpResponse {
    fn from((agent, response): (&Agent, AgentResponseAny)) -> Self {
        let headers = response
            .headers
            .iter()
            .map(|field| (field.0.to_string(), field.1.to_string()))
            .collect::<Vec<(String, String)>>();

        HttpResponse {
            status_code: response.status_code,
            headers,
            body: response.body.clone(),
            has_streaming_body: response.streaming_strategy.is_some(),
            streaming_body: match response.streaming_strategy.is_some() {
                true => Some(HttpResponse::create_body_stream((agent, response))),
                false => None,
            },
        }
    }
}

impl From<&HttpResponse> for Response {
    fn from(http_response: &HttpResponse) -> Self {
        Response {
            status_code: http_response.status_code,
            headers: http_response.headers.clone(),
            body: http_response.body.clone(),
        }
    }
}

impl HttpResponse {
    /// Checks if the `ic-certificate` header is set for the response.
    pub fn has_ic_certificate(&self) -> bool {
        for (header_name, _) in &self.headers {
            if header_name.eq_ignore_ascii_case(IC_CERTIFICATE_HEADER_NAME) {
                return true;
            }
        }

        false
    }

    /// Resolves the correct body stream taking into account the streaming strategy.
    fn create_body_stream((agent, response): (&Agent, AgentResponseAny)) -> Body {
        let initial_body = response.body.clone();
        match response.streaming_strategy {
            Some(StreamingStrategy::Callback(callback)) => {
                let body = futures::stream::once(async move { Ok(initial_body) });
                Body::wrap_stream(
                    body.chain(futures::stream::try_unfold(
                        (agent.clone(), callback.callback.0, Some(callback.token)),
                        move |(agent, callback, callback_token)| async move {
                            let callback_token = match callback_token {
                                Some(callback_token) => callback_token,
                                None => return Ok(None),
                            };

                            let canister = HttpRequestCanister::create(&agent, callback.principal);
                            match canister
                                .http_request_stream_callback(&callback.method, callback_token)
                                .call()
                                .await
                            {
                                Ok((StreamingCallbackHttpResponse { body, token },)) => {
                                    Ok(Some((body, (agent, callback, token))))
                                }
                                Err(e) => {
                                    warn!("Error happened during streaming: {:?}", e);
                                    Err(e)
                                }
                            }
                        },
                    ))
                    .take(MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT)
                    .map(|x| async move { x })
                    .buffered(STREAM_CALLBACK_BUFFER),
                )
            }
            None => Body::from(initial_body),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::http::headers::IC_CERTIFICATE_HEADER_NAME;
    use crate::http::response::HttpResponse;

    #[test]
    fn response_has_ic_certificate() {
        let response = HttpResponse {
            status_code: 200,
            headers: vec![(IC_CERTIFICATE_HEADER_NAME.to_string(), "".to_string())],
            streaming_body: None,
            has_streaming_body: false,
            body: Vec::new(),
        };

        assert!(response.has_ic_certificate());
    }

    #[test]
    fn response_without_ic_certificate() {
        let response = HttpResponse {
            status_code: 200,
            headers: Vec::new(),
            streaming_body: None,
            has_streaming_body: false,
            body: Vec::new(),
        };

        assert!(!response.has_ic_certificate());
    }
}
