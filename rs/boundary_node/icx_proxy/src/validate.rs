use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use candid::Principal;
use ic_agent::Agent;
use ic_response_verification::{
    types::VerificationInfo, verify_request_response_pair, MIN_VERIFICATION_VERSION,
};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

pub trait Validate: Sync + Send {
    fn validate(
        &self,
        agent: &Agent,
        canister_id: &Principal,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<Option<VerificationInfo>, Cow<'static, str>>;
}

#[derive(Clone, Default)]
pub struct Validator {}

impl Validator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Validate for Validator {
    fn validate(
        &self,
        agent: &Agent,
        canister_id: &Principal,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<Option<VerificationInfo>, Cow<'static, str>> {
        if cfg!(feature = "skip_body_verification") {
            return Ok(None);
        }

        match (
            request.is_certification_required(),
            response.has_ic_certificate(),
        ) {
            // TODO: Remove this (FOLLOW-483)
            // Canisters don't have to provide certified variables
            // This should change in the future, grandfathering in current implementations
            (false, false) => Ok(None),
            (_, _) => {
                let ic_public_key = agent.read_root_key();
                let verification_info = verify_request_response_pair(
                    request.into(),
                    response.into(),
                    canister_id.as_slice(),
                    get_current_time_in_ns(),
                    MAX_CERT_TIME_OFFSET_NS,
                    ic_public_key.as_slice(),
                    MIN_VERIFICATION_VERSION,
                )
                .map_err(|_| "Body does not pass verification")?;
                Ok(Some(verification_info))
            }
        }
    }
}

fn get_current_time_in_ns() -> u128 {
    let start = SystemTime::now();

    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use crate::http::request::HttpRequest;
    use crate::http::response::HttpResponse;
    use axum::body::Body;
    use candid::Principal;
    use hyper::Uri;
    use ic_agent::{agent::http_transport::hyper_transport::HyperTransport, Agent};

    use crate::validate::{Validate, Validator};

    #[test]
    fn validate_nop() {
        let canister_id = Principal::from_text("wwc2m-2qaaa-aaaac-qaaaa-cai").unwrap();
        let url = "http://www.example.com";
        let transport = HyperTransport::<Body>::create(url).unwrap();
        let agent = Agent::builder().with_transport(transport).build().unwrap();
        let validator = Validator::new();

        let out = validator.validate(
            &agent,
            &canister_id,
            &HttpRequest {
                uri: Uri::from_static(url),
                method: String::from("GET"),
                body: Vec::new(),
                headers: Vec::new(),
            },
            &HttpResponse {
                status_code: 200,
                headers: Vec::new(),
                streaming_body: None,
                has_streaming_body: false,
                body: Vec::new(),
            },
        );

        assert!(matches!(out, Ok(None)));
    }
}
