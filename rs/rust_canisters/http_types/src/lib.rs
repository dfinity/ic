use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
}

impl HttpRequest {
    pub fn path(&self) -> &str {
        match self.url.find('?') {
            None => &self.url[..],
            Some(index) => &self.url[..index],
        }
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
}

pub struct HttpResponseBuilder(HttpResponse);

impl HttpResponseBuilder {
    pub fn ok() -> Self {
        Self(HttpResponse {
            status_code: 200,
            headers: vec![],
            body: ByteBuf::default(),
        })
    }

    pub fn not_found() -> Self {
        Self(HttpResponse {
            status_code: 404,
            headers: vec![],
            body: ByteBuf::from("not found"),
        })
    }

    pub fn server_error(reason: impl ToString) -> Self {
        Self(HttpResponse {
            status_code: 500,
            headers: vec![],
            body: ByteBuf::from(reason.to_string()),
        })
    }

    pub fn header(mut self, name: impl ToString, value: impl ToString) -> Self {
        self.0.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.0.body = ByteBuf::from(bytes.into());
        self
    }

    pub fn with_body_and_content_length(self, bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        self.header("Content-Length", bytes.len()).body(bytes)
    }

    pub fn build(self) -> HttpResponse {
        self.0
    }
}
