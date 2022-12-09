use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use instant_acme::{
    Account, Authorization, Challenge, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use rcgen::{Certificate, CertificateParams, DistinguishedName};

#[async_trait]
pub trait Order: Sync + Send {
    async fn order(&self, name: &str) -> Result<String, Error>;
}

#[async_trait]
pub trait Ready: Sync + Send {
    async fn ready(&self, name: &str) -> Result<(), Error>;
}

#[async_trait]
pub trait Finalize: Sync + Send {
    async fn finalize(&self, name: &str) -> Result<(String, String), Error>;
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
        let (mut order, state) = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        let authorizations = order
            .authorizations(&state.authorizations)
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
        let (mut order, state) = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        let authorizations = order
            .authorizations(&state.authorizations)
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
    async fn finalize(&self, name: &str) -> Result<(String, String), Error> {
        // Get Order
        let (mut order, state) = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(name.to_string())],
            })
            .await
            .context("failed to create new order")?;

        if state.status != OrderStatus::Ready {
            return Err(anyhow!("order is not ready"));
        }

        let cert = Certificate::from_params({
            let mut params = CertificateParams::new(vec![name.to_string()]);
            params.distinguished_name = DistinguishedName::new();
            params
        })?;

        let csr = cert.serialize_request_der()?;

        let cert_chain_pem = order
            .finalize(&csr, &state.finalize)
            .await
            .context("failed to finalize order")?;

        Ok((
            cert_chain_pem,                   // Certificate Chain
            cert.serialize_private_key_pem(), // Private Key
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
