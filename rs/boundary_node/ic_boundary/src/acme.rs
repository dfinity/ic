use std::time::Instant;

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use instant_acme::{
    Account, Authorization, Challenge, ChallengeType, Identifier, NewOrder, OrderStatus,
};

use crate::core::{WithRetry, WithThrottle};
pub struct OrderHandle(#[allow(dead_code)] instant_acme::Order);

#[derive(Debug)]
pub struct ChallengeResponse {
    #[allow(dead_code)]
    pub token: String,
    #[allow(dead_code)]
    pub key_authorization: String,
}

#[async_trait]
pub trait Order: Sync + Send {
    // TODO: Only used in specific configurations.
    #[allow(dead_code)]
    async fn order(&self, name: &str) -> Result<(OrderHandle, ChallengeResponse), Error>;
}

#[async_trait]
pub trait Ready: Sync + Send {
    // TODO: Only used in specific configurations.
    #[allow(dead_code)]
    async fn ready(&self, order: &mut OrderHandle) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum FinalizeError {
    #[allow(dead_code)]
    #[error("order not ready: {0}")]
    OrderNotReady(String),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Finalize: Sync + Send {
    async fn finalize(&mut self, order: &mut OrderHandle, csr: &[u8]) -> Result<(), FinalizeError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ObtainError {
    #[allow(dead_code)]
    #[error("order not valid: {0}")]
    OrderNotValid(String),

    #[allow(dead_code)]
    #[error("certificate not ready")]
    CertificateNotReady,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Obtain: Sync + Send {
    async fn obtain(&mut self, order: &mut OrderHandle) -> Result<String, ObtainError>;
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Acme {
    account: Account,
}

#[cfg(feature = "tls")]
impl Acme {
    pub fn new(account: Account) -> Self {
        Self { account }
    }
}

#[async_trait]
impl Order for Acme {
    async fn order(&self, name: &str) -> Result<(OrderHandle, ChallengeResponse), Error> {
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
        let challenge = get_challenge(authorizations, ChallengeType::Http01)
            .context("failed to get  challenge")?;

        let key_auth = order.key_authorization(&challenge).as_str().to_string();

        return Ok((
            OrderHandle(order),
            ChallengeResponse {
                token: challenge.token,
                key_authorization: key_auth,
            },
        ));
    }
}

#[async_trait]
impl Ready for Acme {
    async fn ready(&self, order: &mut OrderHandle) -> Result<(), Error> {
        let authorizations = (order.0)
            .authorizations()
            .await
            .context("failed to retrieve order authorizations")?;

        // Set Challenge Ready
        let challenge = get_challenge(authorizations, ChallengeType::Http01)
            .context("failed to get challenge")?;

        (order.0)
            .set_challenge_ready(&challenge.url)
            .await
            .context("failed to set challenge ready")?;

        Ok(())
    }
}

#[async_trait]
impl Finalize for Acme {
    async fn finalize(&mut self, order: &mut OrderHandle, csr: &[u8]) -> Result<(), FinalizeError> {
        let state = order
            .0
            .refresh()
            .await
            .context("failed to refresh order state")?;

        if state.status != OrderStatus::Ready {
            return Err(FinalizeError::OrderNotReady(format!("{:?}", state.status)));
        }

        order
            .0
            .finalize(csr)
            .await
            .context("failed to finalize order")?;

        Ok(())
    }
}

#[async_trait]
impl Obtain for Acme {
    async fn obtain(&mut self, order: &mut OrderHandle) -> Result<String, ObtainError> {
        let state = (order.0)
            .refresh()
            .await
            .context("failed to refresh order state")?;

        if state.status != OrderStatus::Valid {
            return Err(ObtainError::OrderNotValid(format!("{:?}", state.status)));
        }

        let cert_chain_pem = match (order.0)
            .certificate()
            .await
            .context("failed to retrieve certificate")?
        {
            Some(cert_chain_pem) => cert_chain_pem,
            None => {
                return Err(ObtainError::CertificateNotReady);
            }
        };

        Ok(cert_chain_pem) // Certificate Chain
    }
}

#[allow(dead_code)]
fn get_challenge(
    authorizations: Vec<Authorization>,
    typ: ChallengeType,
) -> Result<Challenge, Error> {
    for authorization in authorizations {
        for challenge in authorization.challenges {
            if challenge.r#type != typ {
                continue;
            }

            return Ok(challenge);
        }
    }

    Err(anyhow!("failed to find challenge"))
}

#[async_trait]
impl<T: Finalize> Finalize for WithRetry<T> {
    async fn finalize(&mut self, order: &mut OrderHandle, csr: &[u8]) -> Result<(), FinalizeError> {
        let start_time = Instant::now();

        loop {
            let out = self.0.finalize(order, csr).await;

            // Timeout
            if start_time.elapsed() > self.1 {
                return out;
            }

            // Retry
            if let Err(FinalizeError::OrderNotReady(_)) = out {
                continue;
            }

            return out;
        }
    }
}

#[async_trait]
impl<T: Obtain> Obtain for WithRetry<T> {
    async fn obtain(&mut self, order: &mut OrderHandle) -> Result<String, ObtainError> {
        let start_time = Instant::now();

        loop {
            let out = self.0.obtain(order).await;

            // Timeout
            if start_time.elapsed() > self.1 {
                return out;
            }

            // Retry
            if matches!(
                out,
                Err(ObtainError::OrderNotValid(_)) | Err(ObtainError::CertificateNotReady)
            ) {
                continue;
            }

            return out;
        }
    }
}

#[async_trait]
impl<T: Finalize> Finalize for WithThrottle<T> {
    async fn finalize(&mut self, order: &mut OrderHandle, csr: &[u8]) -> Result<(), FinalizeError> {
        let current_time = Instant::now();
        let next_time = self.1.next_time.unwrap_or(current_time);

        if next_time > current_time {
            tokio::time::sleep(next_time - current_time).await;
        }
        self.1.next_time = Some(Instant::now() + self.1.throttle_duration);

        self.0.finalize(order, csr).await
    }
}

#[async_trait]
impl<T: Obtain> Obtain for WithThrottle<T> {
    async fn obtain(&mut self, order: &mut OrderHandle) -> Result<String, ObtainError> {
        let current_time = Instant::now();
        let next_time = self.1.next_time.unwrap_or(current_time);

        if next_time > current_time {
            tokio::time::sleep(next_time - current_time).await;
        }
        self.1.next_time = Some(Instant::now() + self.1.throttle_duration);

        self.0.obtain(order).await
    }
}
