use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};
use thiserror;
use url::Url;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum RouteProviderError {
    #[error("No existing routes found")]
    NoExistingRoutesFound,
}

pub trait RouteProvider {
    fn route(&self) -> Result<Url, RouteProviderError>;
}

pub struct RoundRobinRouteProvider {
    routes: Vec<Url>,
    current_idx: AtomicUsize,
}

impl RouteProvider for RoundRobinRouteProvider {
    fn route(&self) -> Result<Url, RouteProviderError> {
        if self.routes.is_empty() {
            return Err(RouteProviderError::NoExistingRoutesFound);
        }
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        Ok(self.routes[prev_idx % self.routes.len()].clone())
    }
}

impl RoundRobinRouteProvider {
    pub fn new<T: AsRef<str>>(routes: Vec<T>) -> Self {
        let routes = routes
            .iter()
            .map(|r| Url::from_str(r.as_ref()).expect("invalid url"))
            .collect();
        Self {
            routes,
            current_idx: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_routes() {
        let provider = RoundRobinRouteProvider::new::<&str>(vec![]);
        let result = provider.route().unwrap_err();
        assert_eq!(result, RouteProviderError::NoExistingRoutesFound);
    }

    #[test]
    fn test_routes_rotation() {
        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"]);
        let url_strings = vec!["https://url1.com", "https://url2.com", "https://url1.com"];
        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| provider.route().expect("failed to get next url"))
            .collect();
        assert_eq!(expected_urls, urls);
    }
}
