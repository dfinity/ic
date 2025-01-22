use attestation::protocol::{
    GenerateAttestationTokenError, GenerateAttestationTokenRequest,
    GenerateAttestationTokenResponse, InitiateGenerateAttestationTokenRequest,
    InitiateGenerateAttestationTokenResponse,
};

trait VerificationCanisterInterface {
    async fn initiate_generate_attestation_token(
        &self,
        request: &InitiateGenerateAttestationTokenRequest,
    ) -> Result<InitiateGenerateAttestationTokenResponse, InitiateGenerateAttestationTokenError>;

    async fn generate_attestation_token(
        &self,
        request: &GenerateAttestationTokenRequest,
    ) -> Result<GenerateAttestationTokenResponse, GenerateAttestationTokenError>;

    async fn get_attestation_token(
        &self,
        request: &FetchAttestationTokenRequest,
    ) -> Result<GenerateAttestationTokenResponse, GenerateAttestationTokenError>;
}
