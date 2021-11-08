/// A representation of the `request_type` of a request. It is used to pass the
/// actual request type back up the call graph to be reported in the metrics in
/// `handle_request`.
///
/// https://sdk.dfinity.org/docs/interface-spec/index.html#request-types
pub(crate) enum ApiReqType {
    /// `read_state`
    ReadState,
    /// `call`
    Call,
    /// `query`
    Query,
    /// In case an error occurred and the request type is unknown.
    Unknown,
}

impl ApiReqType {
    pub(crate) fn as_str(&self) -> &'static str {
        use ApiReqType::*;
        match self {
            ReadState => "read_state",
            Call => "call",
            Query => "query",
            Unknown => "unknown",
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum AppLayer {
    Http,
    Https,
}

impl AppLayer {
    pub(crate) fn as_str(&self) -> &'static str {
        use AppLayer::*;
        match self {
            Http => "http",
            Https => "https",
        }
    }
}

/// What kind of request did the user send?
#[derive(Debug, Copy, Clone)]
pub(crate) enum RequestType {
    /// A "status" request
    Status,
    /// A "submit" request
    Submit,
    /// A "query" request
    Query,
    /// A "read_state" request
    ReadState,
    /// A pre-flight OPTIONS request
    Options,
    /// A request for the dashboard, but one that required a redirection
    RedirectToDashboard,
    /// A direct request for the dashboard
    Dashboard,
    /// A CPU profile request
    Pprof(PprofPage),
    /// A request for the latest Catch-Up Package (CUP)
    CatchUpPackage,
}

impl RequestType {
    pub(crate) fn as_str(&self) -> &'static str {
        use RequestType::*;
        match self {
            Status => "status",
            Submit => "submit",
            ReadState => "read_state",
            Query => "query",
            Options => "options",
            RedirectToDashboard => "redirect_to_dashboard",
            Dashboard => "dashboard",
            Pprof(_) => "pprof",
            CatchUpPackage => "catch-up-package",
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum PprofPage {
    /// `pprof` root page.
    Home,
    /// CPU profile in pprof proto format.
    Profile,
    /// CPU profile as flamegraph.
    Flamegraph,
}

pub(crate) enum ConnectionError {
    TlsHandshake,
    ServingHttpConnection,
    ServingHttpsConnection,
    Accept,
    Peek,
    PeekTimeout,
}

impl ConnectionError {
    pub(crate) fn as_str(&self) -> &'static str {
        use ConnectionError::*;
        match self {
            TlsHandshake => "tls_handshake",
            ServingHttpConnection => "serving_http_connection",
            ServingHttpsConnection => "serving_https_connection",
            Accept => "accept",
            Peek => "peek",
            PeekTimeout => "peek_timeout",
        }
    }
}
