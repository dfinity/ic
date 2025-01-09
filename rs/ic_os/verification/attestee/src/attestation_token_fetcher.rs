use anyhow::Result;
use attestation_token::AttestationToken;
use candid::Encode;
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

    pub async fn fetch(&self) -> Result<AttestationToken> {
        let CANISTER: Principal = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let agent = Agent::builder().build()?;
        let request = attestation::protocol::InitiateGenerateAttestationTokenRequest {};
        agent
            .update(&CANISTER, "initiate_attestation")
            .with_arg(Encode!(&request)?)
            .call_and_wait();
        unimplemented!()
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
