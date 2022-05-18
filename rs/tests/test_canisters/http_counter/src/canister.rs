use candid::parser::types::FuncMode;
use candid::types::Function;
use candid::types::Serializer;
use candid::types::Type;
use candid::CandidType;
use candid::Deserialize;
use candid::Func;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[derive(Debug, Default)]
struct State {
    counter: u128,
}

/// A key-value pair for a HTTP header.
#[derive(Debug, CandidType, Clone, Deserialize)]
pub struct HeaderField(String, String);

impl HeaderField {
    fn new(k: impl Into<String>, v: impl Into<String>) -> Self {
        HeaderField(k.into(), v.into())
    }
}

/// The important components of an HTTP request.
#[derive(Debug, Clone, CandidType, Deserialize)]
struct HttpRequest {
    /// The HTTP method string.
    pub method: String,
    /// The URL that was visited.
    pub url: String,
    /// The request headers.
    pub headers: Vec<HeaderField>,
    /// The request body.
    pub body: Vec<u8>,
}

/// A HTTP response.
#[derive(Debug, Clone, CandidType)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status_code: u16,
    /// The response header map.
    pub headers: Vec<HeaderField>,
    /// The response body.
    pub body: Vec<u8>,
    /// The strategy for streaming the rest of the data, if the full response is to be streamed.
    pub streaming_strategy: Option<StreamingStrategy>,
    /// Whether the query call should be upgraded to an update call.
    pub upgrade: bool,
}

/// A Streaming HTTP response.
#[derive(Debug, Clone, CandidType)]
pub struct StreamingCallbackHttpResponse {
    body: Vec<u8>,
    token: Option<Token>,
}

/// Possible strategies for a streaming response.
#[derive(Debug, Clone, CandidType)]
pub enum StreamingStrategy {
    /// A callback-based streaming strategy, where a callback function is provided for continuing the stream.
    Callback(CallbackStrategy),
}

/// A callback-token pair for a callback streaming strategy.
#[derive(Debug, Clone, CandidType)]
pub struct CallbackStrategy {
    /// The callback function to be called to continue the stream.
    pub callback: Callback,
    /// The token to pass to the function.
    pub token: Token,
}

#[derive(Debug, Clone)]
pub struct Callback(Func);

impl From<&str> for Callback {
    fn from(method: &str) -> Self {
        Callback(Func {
            principal: ic_cdk::api::id(),
            method: method.into(),
        })
    }
}

impl CandidType for Callback {
    fn _ty() -> Type {
        Type::Func(Function {
            modes: vec![FuncMode::Query],
            args: vec![Token::ty()],
            rets: vec![HttpResponse::ty()],
        })
    }
    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        self.0.idl_serialize(serializer)
    }
}

#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct Token {
    // Add whatever fields you'd like
    arbitrary_data: TokenState,
}

#[derive(Debug, Clone, CandidType, Deserialize)]
pub enum TokenState {
    Start,
    Next,
    Last,
}

#[ic_cdk_macros::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let counter = STATE.with(|v| v.borrow().counter);

    if req.method == "POST" {
        return HttpResponse {
            status_code: 200,
            headers: vec![],
            body: vec![],
            streaming_strategy: None,
            upgrade: true,
        };
    }
    if req.method != "GET" {
        return HttpResponse {
            status_code: 400,
            headers: vec![],
            body: vec![],
            streaming_strategy: None,
            upgrade: false,
        };
    }
    if req.url == "/stream" {
        return HttpResponse {
            status_code: 200,
            headers: vec![HeaderField::new("content-type", "text/plain")],
            body: "Counter".into(),
            streaming_strategy: Some(StreamingStrategy::Callback(CallbackStrategy {
                callback: Callback::from("http_streaming"),
                token: Token {
                    arbitrary_data: TokenState::Start,
                },
            })),
            upgrade: false,
        };
    }

    let mut is_gzip = false;
    let mut is_deflate = false;
    for HeaderField(k, v) in req.headers.iter() {
        // This isn't technically correct parsing since we ignore the q factor,
        // but it's good enough for a demo
        if k.eq_ignore_ascii_case("accept-encoding") {
            if v.contains("gzip") {
                is_gzip = true;
            }
            if v.contains("deflate") {
                is_deflate = true;
            }
        }
    }

    if is_gzip {
        HttpResponse {
            status_code: 200,
            headers: vec![ HeaderField::new("content-type", "text/plain"), HeaderField::new("content-encoding", "gzip") ],
            body: b"\x1f\x8b\x08\x00\x98\x02\x1b\x62\x00\x03\x2b\x2c\x4d\x2d\xaa\xe4\x02\x00\xd6\x80\x2b\x05\x06\x00\x00\x00".to_vec(),
            streaming_strategy: None,
            upgrade: false,
        }
    } else if is_deflate {
        todo!()
    } else {
        HttpResponse {
            status_code: 200,
            headers: vec![HeaderField::new("content-type", "text/plain")],
            body: format!("Counter is {}\n", counter).into(),
            streaming_strategy: None,
            upgrade: false,
        }
    }
}

#[ic_cdk_macros::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    STATE.with(|v| {
        let counter = &mut v.borrow_mut().counter;

        let mut is_gzip = false;
        let mut is_deflate = false;
        for HeaderField(k, v) in req.headers.iter() {
            // This isn't technically correct parsing since we ignore the q factor,
            // but it's good enough for a demo
            if k.eq_ignore_ascii_case("accept-encoding") {
                if v.contains("gzip") {
                    is_gzip = true;
                }
                if v.contains("deflate") {
                    is_deflate = true;
                }
            }
        }

        *counter += 1;

        if is_gzip {
            HttpResponse {
                status_code: 200,
                headers: vec![ HeaderField::new("content-type", "text/plain"), HeaderField::new("content-encoding", "gzip") ],
                body: b"\x1f\x8b\x08\x00\x98\x02\x1b\x62\x00\x03\x2b\x2c\x4d\x2d\xaa\xe4\x02\x00\xd6\x80\x2b\x05\x06\x00\x00\x00".to_vec(),
                streaming_strategy: None,
                upgrade: false,
            }
        } else if is_deflate {
            todo!()
        } else {
            HttpResponse {
                status_code: 200,
                headers: vec![ HeaderField::new("content-type", "text/plain") ],
                body: format!("Counter is {}\n", counter).into(),
                streaming_strategy: None,
                upgrade: false,
            }
        }
    })
}

#[ic_cdk_macros::query]
fn http_streaming(token: Token) -> StreamingCallbackHttpResponse {
    let counter = STATE.with(|v| v.borrow().counter);

    match token.arbitrary_data {
        TokenState::Start => StreamingCallbackHttpResponse {
            body: " is ".into(),
            token: Some(Token {
                arbitrary_data: TokenState::Next,
            }),
        },
        TokenState::Next => StreamingCallbackHttpResponse {
            body: counter.to_string().into(),
            token: Some(Token {
                arbitrary_data: TokenState::Last,
            }),
        },
        TokenState::Last => StreamingCallbackHttpResponse {
            body: " streaming\n".into(),
            token: None,
        },
    }
}
