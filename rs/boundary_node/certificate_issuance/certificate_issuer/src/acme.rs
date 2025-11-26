use std::time::{Duration, Instant};

use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use instant_acme::{
    Account, Authorization, Challenge, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use mockall::automock;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::time::sleep;
use tracing::info;
use zeroize::Zeroize;

#[automock]
#[async_trait]
pub trait Order: Sync + Send {
    async fn order(&self, name: &str) -> Result<String, Error>;
}

#[automock]
#[async_trait]
pub trait Ready: Sync + Send {
    async fn ready(&self, name: &str) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizeError {
    #[error("order not ready: {0}")]
    OrderNotReady(String),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
#[async_trait]
pub trait Finalize: Sync + Send {
    async fn finalize(&self, name: &str) -> Result<(String, String), FinalizeError>;
}

#[derive(Clone)]
pub struct Acme {
    account: Account,
}

impl Acme {
    pub fn new(account: Account) -> Self {
        Self { account }
    }
}

#[async_trait]
impl Order for Acme {
    async fn order(&self, name: &str) -> Result<String, Error> {
        // Get Order
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        let authorizations = order
            .authorizations()
            .await
            .context("failed to retrieve order authorizations")?;

        // Get Challenge Key
        let challenge = get_dns_challenge(authorizations).context("failed to get dns challenge")?;
        let key_auth = order.key_authorization(&challenge).dns_value();

        return Ok(key_auth);
    }
}

#[async_trait]
impl Ready for Acme {
    async fn ready(&self, name: &str) -> Result<(), Error> {
        // Get Order
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        let authorizations = order
            .authorizations()
            .await
            .context("failed to retrieve order authorizations")?;

        // Set Challenge Ready
        let challenge = get_dns_challenge(authorizations).context("failed to get dns challenge")?;

        order
            .set_challenge_ready(&challenge.url)
            .await
            .context("failed to set challenge ready")?;

        Ok(())
    }
}

#[async_trait]
impl Finalize for Acme {
    async fn finalize(&self, name: &str) -> Result<(String, String), FinalizeError> {
        // Get Order
        info!(domain = name, "creating new order");
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        // Poll until Ready (or timeout)
        info!(domain = name, "polling for order ready status");
        poll_order(&mut order, OrderStatus::Ready)
            .await
            .inspect(|attempts| {
                info!(
                    domain = name,
                    "polling for order succeeded after {attempts} attempts"
                )
            })
            .context("order is unable to reach 'Ready' status")?;

        // Generate key pair
        let mut key_pair = KeyPair::generate().context("failed to create key pair")?;

        // Generate CSR
        let csr = {
            let mut params = CertificateParams::new(vec![name.to_string()])
                .context("failed to create certificate params")?;

            params.distinguished_name = DistinguishedName::new();
            params.serialize_request(&key_pair)
        }
        .context("failed to generate certificate signing request")?;

        // Finalize order
        info!(domain = name, "finalizing order");
        order
            .finalize(csr.der().as_ref())
            .await
            .context("failed to finalize order")?;

        // Poll until Valid (or timeout)
        info!(domain = name, "polling for order valid status");
        poll_order(&mut order, OrderStatus::Valid)
            .await
            .inspect(|attempts| {
                info!(
                    domain = name,
                    "polling for order valid status succeeded after {attempts} attempts"
                )
            })
            .context("failed to poll order status to Valid")?;

        let cert_chain_pem = match order
            .certificate()
            .await
            .context("failed to retrieve certificate")?
        {
            Some(cert_chain_pem) => cert_chain_pem,
            None => {
                let status = order.state().status;
                return Err(FinalizeError::OrderNotReady(format!(
                    "Certificate unavailable despite previous Valid status, current status {status:?}"
                )));
            }
        };

        // Serialize key pair
        let key_pair_pem = key_pair.serialize_pem();
        key_pair.zeroize();
        Ok((
            cert_chain_pem, // Certificate Chain
            key_pair_pem,   // Key pair
        ))
    }
}

fn get_dns_challenge(authorizations: Vec<Authorization>) -> Result<Challenge, Error> {
    for authorization in authorizations {
        for challenge in authorization.challenges {
            if challenge.r#type != ChallengeType::Dns01 {
                continue;
            }

            return Ok(challenge);
        }
    }

    Err(anyhow!("failed to find challenge"))
}

async fn poll_order(order: &mut instant_acme::Order, expect: OrderStatus) -> anyhow::Result<u32> {
    // Uses a duration slightly shorter than the canister's retry_delay (current IN_PROGRESS_TTL = 10 minutes)
    let timeout = Duration::from_secs(500);
    let max_poll_interval = Duration::from_secs(10);
    // initial polling interval, then doubled: 1 -> 2 -> 4 -> ... -> up to max_poll_interval
    let mut poll_interval = Duration::from_secs(1);
    let start_time = Instant::now();
    let mut attempt = 1;

    loop {
        match order.refresh().await {
            Ok(v) => {
                if v.status == expect {
                    return Ok(attempt);
                }

                if v.status == OrderStatus::Invalid {
                    return Err(anyhow!(
                        "Order status is 'Invalid' after {attempt} attempts"
                    ));
                }

                if start_time.elapsed() >= timeout {
                    return Err(anyhow!(
                        "Order status polling timed out on attempt {attempt}, last status '{:?}'",
                        v.status
                    ));
                }
            }
            Err(e) => {
                if start_time.elapsed() >= timeout {
                    return Err(anyhow!(
                        "Unable to get order state on attempt {attempt}: {e:#}"
                    ));
                }
            }
        }
        sleep(poll_interval).await;
        poll_interval = max_poll_interval.min(2 * poll_interval);
        attempt += 1;
    }
}
