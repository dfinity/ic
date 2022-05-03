/// A representation of the `request_type` of a request. It is used to pass the
/// actual request type back up the call graph to be reported in the metrics in
/// `handle_request`.
///
/// https://sdk.dfinity.org/docs/interface-spec/index.html#request-types
use strum::IntoStaticStr;

#[derive(Clone, Copy, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ApiReqType {
    /// `call`
    Call,
    /// `query`
    Query,
    /// `read_state`
    ReadState,
    /// In case an error occurred and the request type is unknown.
    CatchUpPackage,
    Status,
    Dashboard,
    RedirectToDashboard,
    Options,
    PprofHome,
    PprofProfile,
    PprofFlamegraph,
    InvalidArgument,
}

#[derive(Debug, Copy, Clone, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum AppLayer {
    Http,
    Https,
}

// TODO: NET-871
pub(crate) fn to_legacy_request_type(req_type: ApiReqType) -> &'static str {
    match req_type {
        ApiReqType::Call => "submit",
        _ => req_type.into(),
    }
}

#[derive(IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ConnectionError {
    TlsHandshake,
    ServingHttpConnection,
    ServingHttpsConnection,
    Accept,
    Peek,
    PeekTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_label_values_do_not_change() {
        type StaticStr = &'static str;
        assert_eq!(StaticStr::from(ApiReqType::Call), "call");
        assert_eq!(StaticStr::from(ApiReqType::Query), "query");
        assert_eq!(StaticStr::from(ApiReqType::ReadState), "read_state");
        assert_eq!(StaticStr::from(ApiReqType::Status), "status");
        assert_eq!(
            StaticStr::from(ApiReqType::CatchUpPackage),
            "catch_up_package"
        );
        assert_eq!(StaticStr::from(ApiReqType::Options), "options");
        assert_eq!(StaticStr::from(ApiReqType::Dashboard), "dashboard");
        assert_eq!(
            StaticStr::from(ApiReqType::RedirectToDashboard),
            "redirect_to_dashboard"
        );
        assert_eq!(
            StaticStr::from(ApiReqType::InvalidArgument),
            "invalid_argument"
        );
        assert_eq!(StaticStr::from(ApiReqType::PprofHome), "pprof_home");
        assert_eq!(StaticStr::from(ApiReqType::PprofProfile), "pprof_profile");
        assert_eq!(
            StaticStr::from(ApiReqType::PprofFlamegraph),
            "pprof_flamegraph"
        );

        assert_eq!(to_legacy_request_type(ApiReqType::Call), "submit");

        assert_eq!(StaticStr::from(AppLayer::Http), "http");
        assert_eq!(StaticStr::from(AppLayer::Https), "https");

        assert_eq!(
            StaticStr::from(ConnectionError::TlsHandshake),
            "tls_handshake"
        );
        assert_eq!(
            StaticStr::from(ConnectionError::ServingHttpConnection),
            "serving_http_connection"
        );
        assert_eq!(
            StaticStr::from(ConnectionError::ServingHttpsConnection),
            "serving_https_connection"
        );
        assert_eq!(StaticStr::from(ConnectionError::Accept), "accept");
        assert_eq!(StaticStr::from(ConnectionError::Peek), "peek");
        assert_eq!(
            StaticStr::from(ConnectionError::PeekTimeout),
            "peek_timeout"
        );
    }
}
