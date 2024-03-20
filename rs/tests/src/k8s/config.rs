use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::env::var;

pub static TNET_NAMESPACE: Lazy<String> =
    Lazy::new(|| var("TNET_NAMESPACE").unwrap_or("tnets".to_string()));

pub static TNET_CDN_URL: Lazy<String> =
    Lazy::new(|| var("TNET_CDN_URL").unwrap_or("https://download.dfinity.systems".to_string()));

pub static TNET_CONFIG_URL: Lazy<String> = Lazy::new(|| {
    var("TNET_CONFIG_URL").unwrap_or("https://objects.sf1-idx1.dfinity.network".to_string())
});

pub static TNET_DNS_SUFFIX: Lazy<String> =
    Lazy::new(|| var("TNET_DNS_SUFFIX").unwrap_or("tnets.sf1-idx1.dfinity.network".to_string()));

pub static TNET_BUCKET: Lazy<String> = Lazy::new(|| {
    var("TNET_BUCKET").unwrap_or("tnet-config-5f1a0cb6-fdf2-4ca8-b816-9b9c2ffa1669".to_string())
});

pub static TNET_STATIC_LABELS: Lazy<BTreeMap<String, String>> =
    Lazy::new(|| BTreeMap::from([("app".to_string(), "tnet".to_string())]));

pub static TNET_NAME_LABEL: &str = "tnet.internetcomputer.org/name";

pub static TNET_TERMINATE_TIME_ANNOTATION: &str = "tnet.internetcomputer.org/terminate-time";
