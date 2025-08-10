use anyhow::{Context, Error};
use async_trait::async_trait;
use reqwest::{Client, Request, Response};

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, Error>;
}

pub struct ReqwestClient(pub Client);

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, Error> {
        self.0
            .execute(req)
            .await
            .context("failed to execute request")
    }
}
