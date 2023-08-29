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
    Threads,
    InvalidArgument,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnError;

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
        assert_eq!(StaticStr::from(ApiReqType::Threads), "threads");

        assert_eq!(StaticStr::from(ConnError::TlsHandshake), "tls_handshake");
        assert_eq!(StaticStr::from(ConnError::Io), "io");
        assert_eq!(StaticStr::from(ConnError::Timeout), "timeout");
    }
}
