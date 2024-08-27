use crate::common::constants::MAX_ROSETTA_SYNC_ATTEMPTS;
use ic_agent::agent::http_transport::ReqwestTransport;
use ic_agent::identity::BasicIdentity;
use ic_agent::Agent;
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaClient;
use rosetta_core::identifiers::NetworkIdentifier;
use std::sync::Arc;
use url::Url;

pub fn test_identity() -> BasicIdentity {
    BasicIdentity::from_pem(
        &b"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIJKDIfd1Ybt48Z23cVEbjL2DGj1P5iDYmthcrptvBO3z
oSMDIQCJuBJPWt2WWxv0zQmXcXMjY+fP0CJSsB80ztXpOFd2ZQ==
-----END PRIVATE KEY-----"[..],
    )
    .expect("failed to parse identity from PEM")
}

pub async fn get_custom_agent(basic_identity: Arc<dyn Identity>, port: u16) -> Agent {
    // The local replica will be running on the localhost
    let replica_url = Url::parse(&format!("http://localhost:{}", port)).unwrap();

    // Setup the agent
    let transport = ReqwestTransport::create(replica_url.clone()).unwrap();
    let agent = Agent::builder()
        .with_identity(basic_identity)
        .with_arc_transport(Arc::new(transport))
        .build()
        .unwrap();

    // For verification the agent needs the root key of the IC running on the local replica
    agent.fetch_root_key().await.unwrap();
    agent
}

pub async fn wait_for_rosetta_block(
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
    block_index: u64,
) -> Option<u64> {
    for _ in 0..MAX_ROSETTA_SYNC_ATTEMPTS {
        let response = rosetta_client
            .network_status(network_identifier.clone())
            .await;
        if let Ok(status) = response {
            let last_block = status.current_block_identifier.index;
            if last_block >= block_index {
                return Some(last_block);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("Failed to sync with the ledger");
}
