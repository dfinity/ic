use std::{net::IpAddr, path::PathBuf};

use anyhow::Error;
use maxminddb::geoip2;

pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(db_path: PathBuf) -> Result<Self, Error> {
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
