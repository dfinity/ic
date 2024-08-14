use std::time::Duration;

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use instant_acme::{
    Account, Authorization, Challenge, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use mockall::automock;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::time::sleep;
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
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        let state = order
            .refresh()
            .await
            .context("failed to refresh order state")?;

        if state.status != OrderStatus::Ready {
            return Err(FinalizeError::OrderNotReady(format!("{:?}", state.status)));
        }

        let mut key_pair = KeyPair::generate().context("failed to create key pair")?;

        let csr = {
            let mut params = CertificateParams::new(vec![name.to_string()])
                .context("failed to create certificate params")?;

            params.distinguished_name = DistinguishedName::new();
            params.serialize_request(&key_pair)
        }
        .context("failed to generate certificate signing request")?;

        order
            .finalize(csr.der().as_ref())
            .await
            .context("failed to finalize order")?;

        // Inject artificial delay of 5 seconds to allow certificate processing to complete
        sleep(Duration::from_secs(5)).await;

        let cert_chain_pem = match order
            .certificate()
            .await
            .context("failed to retrieve certificate")?
        {
            Some(cert_chain_pem) => cert_chain_pem,
            None => {
                return Err(FinalizeError::OrderNotReady(format!(
                    "{:?}",
                    order.state().status
                )));
            }
        };

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
