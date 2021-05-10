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

impl std::string::ToString for ApiReqType {
    fn to_string(&self) -> String {
        use ApiReqType::*;
        match self {
            ReadState => "read_state",
            Call => "call",
            Query => "query",
            Unknown => "unknown",
        }
        .to_string()
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum AppLayer {
    HTTP,
    HTTPS,
}

impl std::string::ToString for AppLayer {
    fn to_string(&self) -> String {
        use AppLayer::*;
        match self {
            HTTP => "http",
            HTTPS => "https",
        }
        .to_string()
    }
}

/// What kind of request did the user send?
#[derive(Debug, Copy, Clone)]
pub(crate) enum RequestType {
    /// A "status" request
    Status,
    /// A "submit" request
    Submit,
    /// A "read" request
    Read,
    /// A pre-flight OPTIONS request
    Options,
    /// A request for the dashboard, but one that required a redirection
    RedirectToDashboard,
    /// A direct request for the dashboard
    Dashboard,
    /// A request for the latest Catch-Up Package (CUP)
    CatchUpPackage,
}

impl std::string::ToString for RequestType {
    fn to_string(&self) -> String {
        use RequestType::*;
        match self {
            Status => "status",
            Submit => "submit",
            Read => "read",
            Options => "options",
            RedirectToDashboard => "redirect_to_dashboard",
            Dashboard => "dashboard",
            CatchUpPackage => "catch-up-package",
        }
        .to_string()
    }
}

pub(crate) enum ConnectionError {
    TlsHandshake,
    ServingHttpConnection,
    ServingHttpsConnection,
    Accept,
    ClientAuthentication,
}

impl std::string::ToString for ConnectionError {
    fn to_string(&self) -> String {
        use ConnectionError::*;
        match self {
            TlsHandshake => "tls_handshake",
            ServingHttpConnection => "serving_http_connection",
            ServingHttpsConnection => "serving_https_connection",
            Accept => "accept",
            ClientAuthentication => "client_authentication",
        }
        .to_string()
    }
}

pub(crate) enum InternalError {
    Routing,
    ConcurrentTaskExecution,
}

impl std::string::ToString for InternalError {
    fn to_string(&self) -> String {
        use InternalError::*;
        match self {
            Routing => "routing",
            ConcurrentTaskExecution => "concurrent_task_execution",
        }
        .to_string()
    }
}
