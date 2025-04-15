use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::env::var;

pub static TNET_NAMESPACE: Lazy<String> =
    Lazy::new(|| var("TNET_NAMESPACE").unwrap_or("tnets".to_string()));

pub static TNET_CDN_URL: Lazy<String> =
    Lazy::new(|| var("TNET_CDN_URL").unwrap_or("https://download.dfinity.systems".to_string()));

pub static TNET_CONFIG_URL: Lazy<String> = Lazy::new(|| {
    var("TNET_CONFIG_URL")
        .unwrap_or("http://rook-ceph-rgw-ceph-store-ec-ext.rook-ceph.svc.cluster.local".to_string())
});

pub static TNET_DNS_SUFFIX: Lazy<String> =
    Lazy::new(|| var("TNET_DNS_SUFFIX").unwrap_or("tnets.dm1-idx1.dfinity.network".to_string()));

pub static LOGS_URL: Lazy<String> = Lazy::new(|| {
    var("TNET_LOGS_URL").unwrap_or("https://grafana.dm1-idx1.dfinity.network/explore?schemaVersion=1&panes=%7B%22z2x%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bnamespace%3D%5C%22tnets%5C%22,%20container%3D%5C%22guest-console-log%5C%22,%20job%3D%5C%22tnets%2F{job}%5C%22%7D%20%7C%3D%20%60%60%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22builder%22%7D%5D,%22range%22:%7B%22from%22:%22now-2h%22,%22to%22:%22now%22%7D%7D%7D&orgId=1".to_string())
});

pub static TNET_BUCKET: Lazy<String> =
    Lazy::new(|| var("TNET_BUCKET").unwrap_or("tnets".to_string()));

pub static TNET_STATIC_LABELS: Lazy<BTreeMap<String, String>> =
    Lazy::new(|| BTreeMap::from([("app".to_string(), "tnet".to_string())]));

pub static TNET_NAME_LABEL: &str = "tnet.internetcomputer.org/name";
pub static TNET_PLAYNET_LABEL: &str = "tnet.internetcomputer.org/playnet";
pub static TNET_PLAYNET_SECRET: &str = "playnet-tls";

pub static TNET_TERMINATE_TIME_ANNOTATION: &str = "tnet.internetcomputer.org/terminate-time";
