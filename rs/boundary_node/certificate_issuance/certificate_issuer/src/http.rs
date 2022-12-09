use async_trait::async_trait;
use hyper::{client::connect::Connect, Body, Request, Response};

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error>;
}

pub struct HyperClient<T> {
    c: hyper::Client<T>,
}

impl<T> HyperClient<T> {
    pub fn new(c: hyper::Client<T>) -> Self {
        Self { c }
    }
}

#[async_trait]
impl<T> HttpClient for HyperClient<T>
where
    T: Connect + Clone + Send + Sync + 'static,
{
    async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        self.c.request(req).await
    }
}
