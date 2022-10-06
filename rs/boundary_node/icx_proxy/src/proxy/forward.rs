use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use axum::{extract::ConnectInfo, Extension};
use hyper::{
    header::{Entry, HeaderValue},
    http::uri::Parts,
    HeaderMap, Request, Response, Uri,
};
use tracing::{info, instrument};

use crate::{
    http_client::{Body, HyperService},
    proxy::HandleError,
};

pub struct ArgsInner<C> {
    pub debug: bool,
    pub counter: AtomicUsize,
    pub proxy_urls: Vec<Uri>,
    pub client: C,
}
pub struct Args<C> {
    args: Arc<ArgsInner<C>>,
    current: usize,
}
impl<C> From<ArgsInner<C>> for Args<C> {
    fn from(args: ArgsInner<C>) -> Self {
        Args {
            args: Arc::new(args),
            current: 0,
        }
    }
}
impl<C> Clone for Args<C> {
    fn clone(&self) -> Self {
        let args = self.args.clone();
        Args {
            current: args.counter.fetch_add(1, Ordering::Relaxed) % args.proxy_urls.len(),
            args,
        }
    }
}
impl<C> Args<C> {
    fn proxy_url(&self) -> &Uri {
        &self.args.proxy_urls[self.current]
    }
}

#[instrument(level = "info", skip_all, fields(addr = display(addr)))]
pub async fn handler<C: HyperService<Body>>(
    Extension(args): Extension<Arc<Args<C>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let proxy_url = args.proxy_url();
    let args = &args.args;

    async {
        info!("forwarding");
        let proxied_request = create_proxied_request(&addr.ip(), proxy_url.clone(), request)?;
        let response = args.client.clone().call(proxied_request).await?;
        Ok(response)
    }
    .await
    .handle_error(args.debug)
    .map(|b| b.into())
}

fn create_proxied_request<B>(
    client_ip: &IpAddr,
    proxy_url: Uri,
    mut request: Request<B>,
) -> Result<Request<B>, anyhow::Error> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(proxy_url, &request)?;

    let x_forwarded_for_header_name = "x-forwarded-for";

    // Add forwarding information in the headers
    match request.headers_mut().entry(x_forwarded_for_header_name) {
        Entry::Vacant(entry) => {
            entry.insert(client_ip.to_string().parse()?);
        }

        Entry::Occupied(mut entry) => {
            let addr = format!("{}, {}", entry.get().to_str()?, client_ip);
            entry.insert(addr.parse()?);
        }
    }

    Ok(request)
}

fn is_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn remove_hop_headers(headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    let mut result = HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k.as_str()) {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

fn forward_uri<B>(proxy_url: Uri, req: &Request<B>) -> Result<Uri, anyhow::Error> {
    let mut parts = Parts::from(proxy_url);
    parts.path_and_query = req.uri().path_and_query().cloned();
    Ok(Uri::from_parts(parts)?)
}
