use anyhow::bail;
use ic_crypto_tree_hash::{LookupStatus, MixedHashTree, Path};
use ic_types::{
    PrincipalId,
    messages::{
        Blob, Certificate, HttpCallContent, HttpCanisterUpdate, HttpReadState,
        HttpReadStateContent, HttpReadStateResponse, HttpRequestEnvelope,
    },
    time::current_time,
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use slog::{Logger, info};
use std::time::Duration;
use tokio::time::sleep;

const INGRESS_EXPIRY_DURATION: Duration = Duration::from_secs(300);
const APPLICATION_CBOR: &str = "application/cbor";
const SENDER: PrincipalId = PrincipalId::new_anonymous();
const ARG: Vec<u8> = vec![];

pub(crate) struct V2CallAgent {
    client: reqwest::Client,
    addr: String,
    logger: Logger,
}

impl V2CallAgent {
    pub(crate) fn new(client: reqwest::Client, addr: String, logger: Logger) -> Self {
        Self {
            client,
            addr,
            logger,
        }
    }

    pub(crate) async fn call(
        &self,
        canister_id: PrincipalId,
        method_name: String,
    ) -> anyhow::Result<()> {
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

        let update = HttpCanisterUpdate {
            canister_id: Blob(canister_id.into_vec()),
            method_name: method_name.clone(),
            ingress_expiry,
            arg: Blob(ARG),
            sender: Blob(SENDER.into_vec()),
            nonce: None,
        };

        // Try submitting update call to V2 endpoint
        let mut retries_left = 10;
        loop {
            let call_envelope = HttpRequestEnvelope {
                content: HttpCallContent::Call {
                    update: update.clone(),
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };
            let body = serde_cbor::to_vec(&call_envelope).unwrap();

            let url = format!("https://{}/api/v2/canister/{}/call", self.addr, canister_id);

            let request = self
                .client
                .post(url.clone())
                .body(body.clone())
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await
                .unwrap();

            let status = request.status();

            // IC processes the update call on the V2 endpoint IFF the response status is Accepted.
            if status == StatusCode::ACCEPTED {
                break;
            } else {
                info!(
                    self.logger,
                    "Failed to send update call to {url}. status: {status}"
                );
                if retries_left == 0 {
                    let body = request.text().await.unwrap();
                    bail!("Failed to send update call to {url}. status: {status}, body: {body}");
                } else {
                    retries_left -= 1;
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        // Try polling for the status of the update call.
        let mut retries_left = 10;
        loop {
            let message_id = update.id();
            let path = Path::new(vec!["request_status".into(), message_id.clone().into()]);

            let envelope = HttpRequestEnvelope {
                content: HttpReadStateContent::ReadState {
                    read_state: HttpReadState {
                        paths: vec![path],
                        sender: Blob(SENDER.into_vec()),
                        ingress_expiry,
                        nonce: None,
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let body = serde_cbor::to_vec(&envelope).unwrap();
            let url = format!(
                "https://{}/api/v2/canister/{}/read_state",
                self.addr, canister_id
            );

            let response = self
                .client
                .post(url.clone())
                .body(body.clone())
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await
                .unwrap();

            let status = response.status();
            // Parse the response.
            if status == StatusCode::OK {
                let response_body = response.bytes().await.unwrap();
                let response: HttpReadStateResponse =
                    serde_cbor::from_slice(&response_body).unwrap();

                let certificate: Certificate =
                    serde_cbor::from_slice(response.certificate.as_ref()).unwrap();

                let tree = certificate.tree;
                info!(self.logger, "Tree: {:?}", tree);

                let status_path = [&b"request_status"[..], message_id.as_ref(), &b"status"[..]];

                match tree.lookup(&status_path) {
                    LookupStatus::Found(MixedHashTree::Leaf(status)) => {
                        let status =
                            String::from_utf8(status.clone()).expect("Status is valid utf8");
                        if ["replied", "done", "pruned"].contains(&status.as_str()) {
                            return Ok(());
                        } else if "rejected" == status {
                            bail!("Call was rejected");
                        } else {
                            info!(self.logger, "Status not done: {status}",);
                        }
                    }
                    LookupStatus::Found(_) => {
                        bail!("Status not a leaf. This is a bug in the returned state.".to_string())
                    }
                    status @ LookupStatus::Absent | status @ LookupStatus::Unknown => {
                        info!(self.logger, "Status not found: {:?}", status);
                    }
                }
            } else {
                info!(
                    self.logger,
                    "Failed to read state to {url}. Status: {status}"
                );
            }

            if retries_left == 0 {
                bail!("Failed to get a certificate for the update call after 10 retries");
            } else {
                retries_left -= 1;
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
