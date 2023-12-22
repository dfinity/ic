use std::io::Write;

use candid::{
    types::{Serializer, Type},
    CandidType, Func,
};
use flate2::{
    write::{DeflateEncoder, GzEncoder},
    Compression,
};
use serde::Deserialize;

use crate::chunk::ChunkWriter;

const STREAMING_CHUNK_SIZE: usize = 10;

/// A key-value pair for a HTTP header.
#[derive(Debug, CandidType, Clone, Deserialize)]
struct HeaderField(String, String);

impl HeaderField {
    fn new(k: impl Into<String>, v: impl Into<String>) -> Self {
        HeaderField(k.into(), v.into())
    }
}

/// The important components of an HTTP request.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct HttpRequest {
    /// The HTTP method string.
    method: String,
    /// The URL that was visited.
    url: String,
    /// The request headers.
    headers: Vec<HeaderField>,
    /// The request body.
    body: Vec<u8>,
}

/// A HTTP response.
#[derive(Debug, Clone, CandidType)]
pub struct HttpResponse {
    /// The HTTP status code.
    status_code: u16,
    /// The response header map.
    headers: Vec<HeaderField>,
    /// The response body.
    body: Vec<u8>,
    /// The strategy for streaming the rest of the data, if the full response is to be streamed.
    streaming_strategy: Option<StreamingStrategy>,
    /// Whether the query call should be upgraded to an update call.
    upgrade: bool,
}

/// A Streaming HTTP response.
#[derive(Debug, Clone, CandidType)]
pub struct StreamingCallbackHttpResponse {
    body: Vec<u8>,
    token: Option<Token>,
}

/// Possible strategies for a streaming response.
#[derive(Debug, Clone, CandidType)]
enum StreamingStrategy {
    /// A callback-based streaming strategy, where a callback function is provided for continuing the stream.
    Callback(CallbackStrategy),
}

/// A callback-token pair for a callback streaming strategy.
#[derive(Debug, Clone, CandidType)]
struct CallbackStrategy {
    /// The callback function to be called to continue the stream.
    callback: Callback,
    /// The token to pass to the function.
    token: Token,
}

#[derive(Debug, Clone)]
struct Callback(Func);

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
        candid::func!((Token) -> (HttpResponse) query)
    }
    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        self.0.idl_serialize(serializer)
    }
}

#[derive(Default, Debug, Clone, CandidType, Deserialize)]
pub struct Token {
    path: String,
    encoding: Option<Encoding>,
    next: usize,
}
#[derive(Debug, Clone, CandidType, Deserialize)]
enum Encoding {
    Gzip,
    Deflate,
}
trait CompressExt {
    fn compress(&self, r: impl Write + Into<Vec<u8>>, value: String) -> Vec<u8>;
}

impl CompressExt for Encoding {
    fn compress(&self, r: impl Write + Into<Vec<u8>>, value: String) -> Vec<u8> {
        match self {
            Encoding::Gzip => {
                let mut e = GzEncoder::new(r, Compression::default());
                e.write_all(value.as_bytes()).unwrap();
                e.finish().unwrap()
            }
            Encoding::Deflate => {
                let mut e = DeflateEncoder::new(r, Compression::default());
                e.write_all(value.as_bytes()).unwrap();
                e.finish().unwrap()
            }
        }
        .into()
    }
}

impl CompressExt for Option<Encoding> {
    fn compress(&self, mut r: impl Write + Into<Vec<u8>>, value: String) -> Vec<u8> {
        match self {
            Some(v) => v.compress(r, value),
            None => {
                r.write_all(value.as_bytes()).unwrap();
                r.into()
            }
        }
    }
}

const ALLOWED_METHODS: &str = "GET, PUT, POST";

pub fn request(req: HttpRequest) -> HttpResponse {
    match req.method.as_str() {
        "PUT" | "POST" => {
            return HttpResponse {
                status_code: 200,
                headers: vec![],
                body: vec![],
                streaming_strategy: None,
                upgrade: true,
            }
        }
        "GET" => {}
        method => {
            return HttpResponse {
                status_code: 405,
                headers: vec![HeaderField::new("Allow", ALLOWED_METHODS)],
                body: format!("{method} not implemented").into(),
                streaming_strategy: None,
                upgrade: false,
            }
        }
    }

    let mut is_gzip = false;
    let mut is_deflate = false;
    let mut skip_certificate = false;
    let mut streaming_strategy = None;
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
        if k.eq_ignore_ascii_case("x-ic-test") {
            if v.eq_ignore_ascii_case("streaming-callback") {
                streaming_strategy = Some(StreamingStrategy::Callback(CallbackStrategy {
                    callback: Callback::from("http_streaming"),
                    token: Token::default(),
                }));
            } else if v.eq_ignore_ascii_case("no-certificate") {
                skip_certificate = true;
            }
        }
    }
    let encoding = if is_gzip {
        Some(Encoding::Gzip)
    } else if is_deflate {
        Some(Encoding::Deflate)
    } else {
        None
    };

    let mut headers = Vec::new();
    if !skip_certificate {
        let cert = base64::encode(crate::cert::get());
        let tree = base64::encode(crate::cert::get_tree(&req.url));
        headers.push(HeaderField::new(
            "ic-certificate",
            format!("certificate=:{cert}:, tree=:{tree}:"),
        ));
    }
    let value = match crate::kv_store::get(&req.url) {
        None => {
            return HttpResponse {
                status_code: 404,
                headers,
                body: format!("'{}' not found", req.url).into(),
                streaming_strategy: None,
                upgrade: false,
            };
        }
        Some(value) => value,
    };

    headers.push(HeaderField::new("content-type", "text/plain"));
    match encoding {
        Some(Encoding::Gzip) => {
            headers.push(HeaderField::new("content-encoding", "gzip"));
        }
        Some(Encoding::Deflate) => {
            headers.push(HeaderField::new("content-encoding", "deflate"));
        }
        None => {}
    }

    match streaming_strategy {
        Some(StreamingStrategy::Callback(mut cs)) => {
            let body = encoding.compress(ChunkWriter::new(0, STREAMING_CHUNK_SIZE), value);

            headers.push(HeaderField::new("x-ic-test", "streaming-callback"));

            cs.token.path = req.url;
            cs.token.encoding = encoding;
            cs.token.next = body.len();

            HttpResponse {
                status_code: 200,
                headers,
                body,
                streaming_strategy: Some(StreamingStrategy::Callback(cs)),
                upgrade: false,
            }
        }
        None => HttpResponse {
            status_code: 200,
            headers,
            body: encoding.compress(Vec::new(), value),
            streaming_strategy: None,
            upgrade: false,
        },
    }
}

pub fn request_update(req: HttpRequest) -> HttpResponse {
    match req.method.as_str() {
        "POST" | "PUT" => {}
        method => {
            return HttpResponse {
                status_code: 405,
                headers: vec![HeaderField::new("Allow", ALLOWED_METHODS)],
                body: format!("{method} not implemented").into(),
                streaming_strategy: None,
                upgrade: false,
            }
        }
    }
    let val = match String::from_utf8(req.body) {
        Ok(body) => body,
        Err(e) => {
            return HttpResponse {
                status_code: 400,
                headers: vec![],
                body: format!("Body was not UTF8: {e}").into(),
                streaming_strategy: None,
                upgrade: false,
            }
        }
    };

    let body = format!("'{}' set to '{val}'", req.url).into();
    crate::cert::put(&req.url, &val);
    crate::kv_store::put(req.url, val);
    HttpResponse {
        status_code: 200,
        headers: vec![],
        body,
        streaming_strategy: None,
        upgrade: false,
    }
}

pub fn streaming(token: Token) -> StreamingCallbackHttpResponse {
    let value = crate::kv_store::get(&token.path).unwrap();

    let body = token
        .encoding
        .compress(ChunkWriter::new(token.next, STREAMING_CHUNK_SIZE), value);
    let token = if body.len() == STREAMING_CHUNK_SIZE {
        Some(Token {
            path: token.path,
            encoding: token.encoding,
            next: token.next + STREAMING_CHUNK_SIZE,
        })
    } else {
        None
    };

    StreamingCallbackHttpResponse { body, token }
}
