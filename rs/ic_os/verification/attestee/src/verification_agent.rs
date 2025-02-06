use attestation::protocol::{
    FetchAttestationTokenRequest, FetchAttestationTokenResponse, GenerateAttestationTokenRequest,
    GenerateAttestationTokenResponse, GenerateTlsCertificateRequest,
    GenerateTlsCertificateResponse, InitiateGenerateAttestationTokenRequest,
    InitiateGenerateAttestationTokenResponse, VerificationError,
};
use candid::{CandidType, Decode, Encode, Error, Principal};
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, AgentError, Identity};
use sha2::Digest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerificationAgentError {
    #[error("AgentError: {0}")]
    AgentError(#[from] AgentError),
    #[error("CanisterError: {0}")]
    CanisterError(#[from] VerificationError),
}

pub type VerificationAgentResult<T> = Result<T, VerificationAgentError>;

#[async_trait::async_trait]
pub trait VerificationAgent: Send + Sync {
    async fn initiate_generate_attestation_token(
        &self,
        request: &InitiateGenerateAttestationTokenRequest,
    ) -> VerificationAgentResult<InitiateGenerateAttestationTokenResponse>;

    async fn generate_attestation_token(
        &self,
        request: &GenerateAttestationTokenRequest,
    ) -> VerificationAgentResult<GenerateAttestationTokenResponse>;

    async fn generate_tls_certificate(
        &self,
        request: &GenerateTlsCertificateRequest,
    ) -> VerificationAgentResult<GenerateTlsCertificateResponse>;

    async fn fetch_attestation_token(
        &self,
        request: &FetchAttestationTokenRequest,
    ) -> VerificationAgentResult<FetchAttestationTokenResponse>;
}

pub struct VerificationCanisterClient {
    verification_canister: Principal,
    agent: Agent,
}

impl VerificationCanisterClient {
    pub fn new(identity: impl Identity + 'static) -> VerificationCanisterClient {
        let agent = Agent::builder()
            .with_url("http://127.0.0.1:4943")
            .with_verify_query_signatures(false)
            .with_identity(identity)
            .build()
            .unwrap();
        Self {
            verification_canister: Principal::from_text("be2us-64aaa-aaaaa-qaabq-cai").unwrap(),
            agent,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum CallType {
    Update,
    Query,
}
impl VerificationCanisterClient {
    async fn call<Request: CandidType, Response: CandidType + for<'a> candid::Deserialize<'a>>(
        &self,
        method_name: &str,
        request: Request,
        call_type: CallType,
    ) -> VerificationAgentResult<Response> {
        // DO NOT SUBMIT:
        self.agent.fetch_root_key().await?;

        println!("ROOT KEY: {:?}", self.agent.read_root_key());

        let result = if call_type == CallType::Update {
            self.agent
                .update(&self.verification_canister, method_name)
                .with_arg(
                    Encode!(&request)
                        .map_err(|err| VerificationAgentError::AgentError(err.into()))?,
                )
                .call_and_wait()
                .await?
        } else {
            self.agent
                .query(&self.verification_canister, method_name)
                .with_arg(
                    Encode!(&request)
                        .map_err(|err| VerificationAgentError::AgentError(err.into()))?,
                )
                .call()
                .await?
        };

        match Decode!(&result, Result<Response, VerificationError>) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(canister_error)) => Err(VerificationAgentError::CanisterError(canister_error)),
            Err(err) => Err(VerificationAgentError::AgentError(AgentError::CandidError(
                err.into(),
            ))),
        }
    }
}

#[async_trait::async_trait]
impl VerificationAgent for VerificationCanisterClient {
    async fn initiate_generate_attestation_token(
        &self,
        request: &InitiateGenerateAttestationTokenRequest,
    ) -> VerificationAgentResult<InitiateGenerateAttestationTokenResponse> {
        self.call(
            "initiate_generate_attestation_token",
            request,
            CallType::Update,
        )
        .await
    }

    async fn generate_attestation_token(
        &self,
        request: &GenerateAttestationTokenRequest,
    ) -> VerificationAgentResult<GenerateAttestationTokenResponse> {
        self.call("generate_attestation_token", request, CallType::Update)
            .await
    }

    async fn generate_tls_certificate(
        &self,
        request: &GenerateTlsCertificateRequest,
    ) -> VerificationAgentResult<GenerateTlsCertificateResponse> {
        self.call("generate_tls_certificate", request, CallType::Update)
            .await
    }

    async fn fetch_attestation_token(
        &self,
        request: &FetchAttestationTokenRequest,
    ) -> VerificationAgentResult<FetchAttestationTokenResponse> {
        self.call("fetch_attestation_token", request, CallType::Query)
            .await
    }
}
