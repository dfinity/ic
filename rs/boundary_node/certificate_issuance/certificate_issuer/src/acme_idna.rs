use crate::acme::{Finalize, FinalizeError, Order, Ready};
use anyhow::{Context, Error};
use async_trait::async_trait;

// Wrapper to convert names to A-label Internalized Domain Names
pub struct WithIDNA<T>(pub T);

#[async_trait]
impl<T: Order> Order for WithIDNA<T> {
    async fn order(&self, name: &str) -> Result<String, Error> {
        // Convert name to A-label Internationalized Domain Name
        let ascii_name = idna::domain_to_ascii(name).context("failed to idna-encode domain")?;
        self.0.order(&ascii_name).await
    }
}

#[async_trait]
impl<T: Ready> Ready for WithIDNA<T> {
    async fn ready(&self, name: &str) -> Result<(), Error> {
        // Convert name to A-label Internationalized Domain Name
        let ascii_name = idna::domain_to_ascii(name).context("failed to idna-encode domain")?;
        self.0.ready(&ascii_name).await
    }
}

#[async_trait]
impl<T: Finalize> Finalize for WithIDNA<T> {
    async fn finalize(&self, name: &str) -> Result<(String, String), FinalizeError> {
        // Convert name to A-label Internationalized Domain Name
        let ascii_name = idna::domain_to_ascii(name).context("failed to idna-encode domain")?;
        self.0.finalize(&ascii_name).await
    }
}

#[cfg(test)]
mod tests {
    use crate::acme::{Finalize, MockFinalize, MockOrder, MockReady, Order, Ready};
    use crate::acme_idna::WithIDNA;
    use mockall::predicate;

    /*
     * Check that the wrapper encodes the the parameter correctly and passes it
     * to the wrapped functions
     */

    const DOMAIN: &str = "rüdi";
    const DOMAIN_ENCODED: &str = "xn--rdi-hoa";

    #[tokio::test]
    async fn test_order_with_idna() {
        let mut mock = MockOrder::new();
        mock.expect_order().returning(|x| Ok(x.to_string()));

        let mock = WithIDNA(mock);
        assert_eq!(mock.order(DOMAIN).await.unwrap(), DOMAIN_ENCODED);
    }

    #[tokio::test]
    async fn test_ready_with_idna() {
        let mut mock = MockReady::new();
        mock.expect_ready()
            .with(predicate::eq(DOMAIN_ENCODED))
            .times(1)
            .returning(|_x| Ok(()));

        let mock = WithIDNA(mock);
        mock.ready(DOMAIN).await.unwrap();
    }

    #[tokio::test]
    async fn test_finalize_with_idna() {
        let mut mock = MockFinalize::new();
        mock.expect_finalize()
            .returning(|x| Ok((x.to_string(), x.to_string())));

        let mock = WithIDNA(mock);
        assert_eq!(
            mock.finalize(DOMAIN).await.unwrap(),
            (DOMAIN_ENCODED.to_string(), DOMAIN_ENCODED.to_string())
        );
    }
}
