use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use instant_acme::{
    Account, Authorization, Challenge, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use mockall::automock;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::time::sleep;
use tracing::{error, info};
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
            .context("failed to create new order")
            .map_err(|e| {
                error!(domain = name, error = %e);
                e
            })?;

        // Poll until Ready (or timeout)
        info!(domain = name, "polling for order ready status");
        poll_order(&mut order, OrderStatus::Ready)
            .await
            .context("order is unable to reach 'Ready' status")
            .map_err(|e| {
                error!(domain = name, error = %e);
                e
            })?;

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
            .context("failed to finalize order")
            .map_err(|e| {
                error!(domain = name, error = %e);
                e
            })?;

        // Poll until Valid (or timeout)
        info!(domain = name, "polling for order valid status");
        poll_order(&mut order, OrderStatus::Valid)
            .await
            .context("failed to poll order status to Valid")
            .map_err(|e| {
                error!(domain = name, error = %e);
                e
            })?;

        let cert_chain_pem = match order
            .certificate()
            .await
            .context("failed to retrieve certificate")
            .map_err(|e| {
                error!(domain = name, error = %e);
                e
            })? {
            Some(cert_chain_pem) => {
                info!(domain = name, "Certificate retrieved successfully");
                cert_chain_pem
            }
            None => {
                let status = order.state().status;
                error!(domain = name, status = ?status, "Certificate not available despite Valid status");
                return Err(FinalizeError::OrderNotReady(format!("{:?}", status)));
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

async fn poll_order(order: &mut instant_acme::Order, expect: OrderStatus) -> anyhow::Result<()> {
    let max_wait = Duration::from_secs(60);
    let poll_interval = Duration::from_secs(5);
    let start_time = Instant::now();

    loop {
        match order.refresh().await {
            Ok(v) => {
                if v.status == expect {
                    return Ok(());
                }

                if v.status == OrderStatus::Invalid {
                    return Err(anyhow!("Order status is 'Invalid'"));
                }

                if start_time.elapsed() >= max_wait {
                    return Err(anyhow!("Order status polling timed out: {:?}", v.status));
                }
            }
            Err(e) => {
                if start_time.elapsed() >= max_wait {
                    return Err(anyhow!("Unable to get order state: {e:#}"));
                }
            }
        }
        sleep(poll_interval).await;
    }
}
