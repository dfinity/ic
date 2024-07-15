use crate::http::headers::IC_CERTIFICATE_HEADER_NAME;
use axum::body::Body;
use futures::{stream, Stream, StreamExt, TryStreamExt};
use ic_agent::{Agent, AgentError};
use ic_http_certification::HttpResponse as Response;
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

// Limit the total number of calls to an HTTP request look that can be verified
static MAX_VERIFIED_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT: usize = 4;

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

impl From<&HttpResponse> for Response {
    fn from(http_response: &HttpResponse) -> Self {
        Response {
            status_code: http_response.status_code,
            headers: http_response.headers.clone(),
            body: http_response.body.clone(),
            upgrade: None,
        }
    }
}

impl HttpResponse {
    pub async fn create(agent: &Agent, response: &AgentResponseAny) -> Result<Self, AgentError> {
        let headers = response
            .headers
            .iter()
            .map(|field| (field.0.to_string(), field.1.to_string()))
            .collect::<Vec<(String, String)>>();

        let (body, streaming_body) =
            HttpResponse::get_body_and_streaming_body(agent, response).await?;

        Ok(HttpResponse {
            status_code: response.status_code,
            headers,
            body,
            has_streaming_body: streaming_body.is_some(),
            streaming_body,
        })
    }

    /// Checks if the `ic-certificate` header is set for the response.
    pub fn has_ic_certificate(&self) -> bool {
        for (header_name, _) in &self.headers {
            if header_name.eq_ignore_ascii_case(IC_CERTIFICATE_HEADER_NAME) {
                return true;
            }
        }

        false
    }

    async fn get_body_and_streaming_body(
        agent: &Agent,
        response: &AgentResponseAny,
    ) -> Result<(Vec<u8>, Option<Body>), AgentError> {
        // if we already have the full body, we can return it early
        let Some(StreamingStrategy::Callback(callback_strategy)) =
            response.streaming_strategy.clone()
        else {
            return Ok((response.body.clone(), None));
        };

        let (streamed_body, token) = HttpResponse::create_stream(
            agent.clone(),
            callback_strategy.callback.clone(),
            Some(callback_strategy.token),
        )
        .take(MAX_VERIFIED_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT)
        .map(|x| async move { x })
        .buffered(STREAM_CALLBACK_BUFFER)
        .try_fold(
            (vec![], None::<Token>),
            |mut accum, (mut body, token)| async move {
                accum.0.append(&mut body);
                accum.1 = token;

                Ok(accum)
            },
        )
        .await?;

        let streamed_body = [response.body.clone(), streamed_body].concat();

        // if we still have a token at this point,
        // we were unable to collect the response within the allowed certified callback limit,
        // fallback to uncertified streaming using what we've streamed so far as the initial body
        if token.is_some() {
            let body_stream = HttpResponse::create_body_stream(
                agent.clone(),
                callback_strategy.callback,
                token,
                streamed_body,
            );

            return Ok((response.body.clone(), Some(body_stream)));
        };

        // if no longer have a token at this point,
        // we were able to collect the response within the allow certified callback limit,
        // return this collected response as a standard response body so it will be verified
        Ok((streamed_body, None))
    }

    fn create_body_stream(
        agent: Agent,
        callback: HttpRequestStreamingCallbackAny,
        token: Option<Token>,
        initial_body: Vec<u8>,
    ) -> Body {
        let chunks_stream = HttpResponse::create_stream(agent, callback, token)
            .map(|chunk| chunk.map(|(body, _)| body));

        Body::from_stream(
            stream::once(async move { Ok(initial_body) })
                .chain(chunks_stream)
                .take(MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT)
                .map(|x| async move { x })
                .buffered(STREAM_CALLBACK_BUFFER),
        )
    }

    fn create_stream(
        agent: Agent,
        callback: HttpRequestStreamingCallbackAny,
        token: Option<Token>,
    ) -> impl Stream<Item = Result<(Vec<u8>, Option<Token>), AgentError>> {
        futures::stream::try_unfold(
            (agent, callback, token),
            |(agent, callback, token)| async move {
                let Some(token) = token else {
                    return Ok(None);
                };

                let canister = HttpRequestCanister::create(&agent, callback.0.principal);
                match canister
                    .http_request_stream_callback(&callback.0.method, token)
                    .call()
                    .await
                {
                    Ok((StreamingCallbackHttpResponse { body, token },)) => {
                        Ok(Some(((body, token.clone()), (agent, callback, token))))
                    }
                    Err(e) => {
                        warn!("Error happened during streaming: {:?}", e);
                        Err(e)
                    }
                }
            },
        )
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
