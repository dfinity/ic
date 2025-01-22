use anyhow::Result;
use attestation::attestation::GenerateAttestationTokenCustomData;
use attestation::protocol::InitiateGenerateAttestationTokenResponse;
use attestation_token::AttestationToken;
use candid::{Decode, Encode};
use der::asn1::OctetStringRef;
use ic_agent::agent::route_provider::RoundRobinRouteProvider;
use ic_agent::agent::AgentConfig;
use ic_agent::export::Principal;
use ic_agent::hash_tree::Label;
use ic_agent::Agent;

pub struct AttestationTokenFetcher {
    firmware: Sev,
}

impl AttestationTokenFetcher {
    pub fn new() -> AttestationTokenFetcher {
        todo!()
    }

    pub async fn fetch(&self, tls_public_key: &[u8]) -> Result<AttestationToken> {
        let CANISTER: Principal = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let agent = Agent::builder().build()?;
        let request = attestation::protocol::InitiateGenerateAttestationTokenRequest {};
        let result = agent
            .update(&CANISTER, "initiate_generate_attestation_token")
            .with_arg(Encode!(&request)?)
            .call_and_wait()
            .await?;
        let mut response: InitiateGenerateAttestationTokenResponse = Decode!(&result)?;

        let nonce = &mut response.challenge.nonce;
        let custom_data_bytes = GenerateAttestationTokenCustomData {
            nonce: OctetStringRef::new(&nonce[..])?,
            tls_public_key: OctetStringRef::new(tls_public_key)?,
        }
        .to_bytes();
        self.firmware
    }
}

#[tokio::test]
async fn test() {
    let result = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .unwrap()
        .read_state_raw(
            vec![vec![
                "canister".into(),
                "rwlgt-iiaaa-aaaaa-aaaaa-cai".into(),
                "certified_data".into(),
            ]],
            Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap(),
        )
        .await
        .unwrap();
    dbg!(result);
}
