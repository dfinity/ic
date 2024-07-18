use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::env::var;

pub static TNET_NAMESPACE: Lazy<String> =
    Lazy::new(|| var("TNET_NAMESPACE").unwrap_or("tnets".to_string()));

pub static TNET_CDN_URL: Lazy<String> =
    Lazy::new(|| var("TNET_CDN_URL").unwrap_or("https://download.dfinity.systems".to_string()));

pub static TNET_CONFIG_URL: Lazy<String> = Lazy::new(|| {
    var("TNET_CONFIG_URL").unwrap_or("https://objects.ln1-idx1.dfinity.network".to_string())
});

pub static TNET_DNS_SUFFIX: Lazy<String> =
    Lazy::new(|| var("TNET_DNS_SUFFIX").unwrap_or("tnets.ln1-idx1.dfinity.network".to_string()));

pub static TNET_BUCKET: Lazy<String> = Lazy::new(|| {
    var("TNET_BUCKET").unwrap_or("tnet-config-8edb8de3-6057-49e4-9fdb-66a29ee9aeda".to_string())
});

pub static TNET_STATIC_LABELS: Lazy<BTreeMap<String, String>> =
    Lazy::new(|| BTreeMap::from([("app".to_string(), "tnet".to_string())]));

pub static TNET_NAME_LABEL: &str = "tnet.internetcomputer.org/name";
pub static TNET_PLAYNET_LABEL: &str = "tnet.internetcomputer.org/playnet";
pub static TNET_PLAYNET_SECRET: &str = "playnet-tls";

pub static TNET_TERMINATE_TIME_ANNOTATION: &str = "tnet.internetcomputer.org/terminate-time";
