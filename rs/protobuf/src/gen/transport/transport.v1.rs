#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpHeader {
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpRequest {
    #[prost(string, tag = "1")]
    pub uri: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
    #[prost(enumeration = "HttpMethod", tag = "3")]
    pub method: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub body: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpResponse {
    #[prost(uint32, tag = "1")]
    pub status_code: u32,
    #[prost(message, repeated, tag = "2")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
    #[prost(bytes = "vec", tag = "3")]
    pub body: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum HttpMethod {
    Unspecified = 0,
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
    Connect = 7,
    Patch = 8,
    Trace = 9,
}
impl HttpMethod {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            HttpMethod::Unspecified => "HTTP_METHOD_UNSPECIFIED",
            HttpMethod::Get => "HTTP_METHOD_GET",
            HttpMethod::Post => "HTTP_METHOD_POST",
            HttpMethod::Put => "HTTP_METHOD_PUT",
            HttpMethod::Delete => "HTTP_METHOD_DELETE",
            HttpMethod::Head => "HTTP_METHOD_HEAD",
            HttpMethod::Options => "HTTP_METHOD_OPTIONS",
            HttpMethod::Connect => "HTTP_METHOD_CONNECT",
            HttpMethod::Patch => "HTTP_METHOD_PATCH",
            HttpMethod::Trace => "HTTP_METHOD_TRACE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "HTTP_METHOD_UNSPECIFIED" => Some(Self::Unspecified),
            "HTTP_METHOD_GET" => Some(Self::Get),
            "HTTP_METHOD_POST" => Some(Self::Post),
            "HTTP_METHOD_PUT" => Some(Self::Put),
            "HTTP_METHOD_DELETE" => Some(Self::Delete),
            "HTTP_METHOD_HEAD" => Some(Self::Head),
            "HTTP_METHOD_OPTIONS" => Some(Self::Options),
            "HTTP_METHOD_CONNECT" => Some(Self::Connect),
            "HTTP_METHOD_PATCH" => Some(Self::Patch),
            "HTTP_METHOD_TRACE" => Some(Self::Trace),
            _ => None,
        }
    }
}
