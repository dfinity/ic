use std::{net::IpAddr, path::PathBuf, sync::Arc};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use bytes::Bytes;
use http::HeaderValue;
use ic_bn_lib::http::headers::{X_IC_COUNTRY_CODE, X_REAL_IP};
use maxminddb::geoip2;

use crate::routes::ApiError;

#[derive(Clone)]
pub struct GeoData {
    pub country_code: String,
}

pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        Ok(Self {
            db: maxminddb::Reader::open_readfile(db_path)?,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> String {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok();

        country
            .and_then(|x| x.country.and_then(|x| x.iso_code))
            .unwrap_or("N/A")
            .into()
    }
}

// TODO add processing of ConnectInfo
pub async fn middleware(
    State(geoip): State<Arc<GeoIp>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    // Try to get & parse client IP from the header
    let client_ip = request
        .headers()
        .get(X_REAL_IP)
        .and_then(|x| x.to_str().ok().and_then(|x| x.parse::<IpAddr>().ok()));

    let country_code = client_ip.map(|x| geoip.lookup(x)).unwrap_or("N/A".into());
    let geo_data = GeoData {
        country_code: country_code.clone(),
    };

    request.extensions_mut().insert(geo_data);
    let mut response = next.run(request).await;

    response.headers_mut().insert(
        X_IC_COUNTRY_CODE,
        HeaderValue::from_maybe_shared(Bytes::from(country_code)).unwrap(),
    );

    Ok(response)
}
