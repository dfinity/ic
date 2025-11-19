use duration_string::DurationString;
use regex;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use serde;
use serde::Deserialize;
use serde::Deserializer;
use serde::de::Error;
use serde::de::Visitor;
use serde_yaml::{self};
use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

#[derive(Debug, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Http,
    Https {
        certificate: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    },
}

impl Clone for Protocol {
    fn clone(&self) -> Self {
        match self {
            Self::Http => Self::Http,
            Self::Https { certificate, key } => Self::Https {
                certificate: certificate.clone(),
                key: key.clone_key(),
            },
        }
    }
}

impl TryFrom<&ListenOn> for Protocol {
    type Error = ListenOnParseError;
    fn try_from(other: &ListenOn) -> Result<Self, Self::Error> {
        let mut scheme = other.url.scheme();
        if scheme.is_empty() {
            scheme = "http";
        }

        match scheme {
            "http" => {
                if other.certificate_file.is_some() || other.key_file.is_some() {
                    Err(Self::Error::SSLOptionsNotAllowed)
                } else {
                    Ok(Self::Http)
                }
            }
            "https" => {
                if other.certificate_file.is_none() {
                    return Err(Self::Error::CertificateFileRequired);
                }
                if other.key_file.is_none() {
                    return Err(Self::Error::KeyFileRequired);
                }
                let certdata = std::fs::read(other.certificate_file.clone().unwrap());
                if let Err(err) = certdata {
                    return Err(Self::Error::CertificateFileReadError(err));
                }

                let mut certs_cursor: Cursor<Vec<u8>> = Cursor::new(certdata.unwrap());
                let certs_loaded = rustls_pemfile::certs(&mut certs_cursor);

                let mut certs_parsed = vec![];
                let mut errors = vec![];
                for maybe_cert in certs_loaded {
                    let cert = match maybe_cert {
                        Ok(cert) => cert,
                        Err(e) => {
                            errors.push(e);
                            continue;
                        }
                    };

                    certs_parsed.push(cert);
                }

                if !errors.is_empty() {
                    return Err(Self::Error::CertificateFileReadError(
                        std::io::Error::other(format!(
                            "Received the following errors: {errors:#?}"
                        )),
                    ));
                }

                if certs_parsed.is_empty() {
                    return Err(Self::Error::CertificateFileReadError(
                        std::io::Error::other(format!(
                            "{} contains no certificates",
                            other.certificate_file.clone().unwrap().display()
                        )),
                    ));
                }

                let key = PrivateKeyDer::from_pem_file(other.key_file.as_ref().unwrap())
                    .map_err(Self::Error::KeyFileReadError)?;

                Ok(Self::Https {
                    certificate: certs_parsed,
                    key,
                })
            }
            _ => Err(Self::Error::InvalidURL(InvalidURLError::UnsupportedScheme(
                scheme.to_owned(),
            ))),
        }
    }
}

#[derive(Debug, Clone)]
/// All possible actions to apply to metrics as part of a client request.
/// Actions in a list of actions are processed from first to last.
pub enum LabelFilterAction {
    /// Keep the metric.
    Keep,
    /// Drop the metric.
    Drop,
    /// Cache the metric for an amount of time.
    ReduceTimeResolution { resolution: DurationString },
    /// Add an amount of random noise to a metric,
    /// in absolute terms.  Should never be used with
    /// counters!
    AddAbsoluteNoise { amplitude: f64, quantum: f64 },
}

impl<'de> Deserialize<'de> for LabelFilterAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LabelFilterActionVistor)
    }
}

struct LabelFilterActionVistor;

impl<'de> Visitor<'de> for LabelFilterActionVistor {
    type Value = LabelFilterAction;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a label filter action such as `keep`, `drop`, `reduce_time_resolution` or `add_absolute_noise`")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match v {
            "keep" => Ok(LabelFilterAction::Keep),
            "drop" => Ok(LabelFilterAction::Drop),
            other => Err(E::custom(format!("unknown action `{}`", other))),
        }
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        // Expect exactly one key in the map
        let key: Option<String> = map.next_key()?;
        let key = key.ok_or_else(|| serde::de::Error::custom("expected an action name"))?;

        match key.as_str() {
            "reduce_time_resolution" => {
                #[derive(Deserialize)]
                struct ReduceTR {
                    resolution: DurationString,
                }

                let value: ReduceTR = map.next_value().map_err(|e| {
                    serde::de::Error::custom(format!("invalid reduce_time_resolution: {}", e))
                })?;

                Ok(LabelFilterAction::ReduceTimeResolution {
                    resolution: value.resolution,
                })
            }

            "add_absolute_noise" => {
                #[derive(Deserialize)]
                struct Noise {
                    amplitude: f64,
                    quantum: f64,
                }

                let value: Noise = map.next_value().map_err(|e| {
                    serde::de::Error::custom(format!("invalid add_absolute_noise: {}", e))
                })?;

                Ok(LabelFilterAction::AddAbsoluteNoise {
                    amplitude: value.amplitude,
                    quantum: value.quantum,
                })
            }

            other => Err(serde::de::Error::custom(format!(
                "unknown action `{}`",
                other
            ))),
        }
    }
}

fn anchored_regex<'de, D>(deserializer: D) -> Result<regex::Regex, D::Error>
where
    D: Deserializer<'de>,
{
    // This regex is to be anchored to ensure people familiar with
    // Prometheus rewrite rules (which this program is inspired by)
    // do not encounter surprises like overmatching.
    let s: String = Deserialize::deserialize(deserializer)?;
    let real = "^".to_string() + &s.to_string() + "$";
    match regex::Regex::new(real.as_str()) {
        Ok(regex) => Ok(regex),
        Err(err) => Err(D::Error::custom(err)),
    }
}

fn default_source_labels() -> Vec<String> {
    vec!["__name__".to_string()]
}

fn default_label_separator() -> String {
    ";".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
/// Match each returned time series (to be processed) according to
/// the listed labels, concatenated according to the separator,
/// and matching with the specified regular expression, anchored
/// at beginning and end.
pub struct LabelFilter {
    #[serde(default = "default_source_labels")]
    pub source_labels: Vec<String>,
    #[serde(default = "default_label_separator")]
    pub separator: String,
    #[serde(deserialize_with = "anchored_regex")]
    pub regex: regex::Regex,
    pub actions: Vec<LabelFilterAction>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(try_from = "ListenOn")]
pub struct ListenerSpec {
    pub protocol: Protocol,
    pub sockaddr: SocketAddr,
    pub header_read_timeout: Duration,
    pub request_response_timeout: Duration,
    pub handler: String,
}

enum InvalidURLError {
    AddrParseError(std::net::AddrParseError),
    AddrResolveError(std::io::Error),
    InvalidAddressError(String),
    UnsupportedScheme(String),
    AuthenticationUnsupported,
    FragmentUnsupported,
}

impl std::fmt::Display for InvalidURLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AddrParseError(e) => {
                write!(f, "cannot parse address: {e}")
            }
            Self::AddrResolveError(e) => {
                write!(f, "cannot resolve address: {e}")
            }
            Self::InvalidAddressError(e) => {
                write!(f, "invalid address: {e}")
            }
            Self::UnsupportedScheme(scheme) => {
                write!(f, "the {scheme} protocol is not supported by this program",)
            }
            Self::AuthenticationUnsupported => {
                write!(f, "authentication is currently not supported")
            }
            Self::FragmentUnsupported => {
                write!(f, "fragments may not be specified")
            }
        }
    }
}

fn default_header_read_timeout() -> DurationString {
    DurationString::new(Duration::new(5, 0))
}

fn default_request_response_timeout() -> DurationString {
    let df: Duration = default_timeout().into();
    DurationString::new(df + Duration::new(5, 0))
}

fn default_cache_duration() -> DurationString {
    DurationString::new(Duration::new(0, 0))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Specifies which host and port to listen on, and on which
/// HTTP handler (path) to respond to.
struct ListenOn {
    url: Url,
    certificate_file: Option<std::path::PathBuf>,
    key_file: Option<std::path::PathBuf>,
    #[serde(default = "default_header_read_timeout")]
    header_read_timeout: DurationString,
    #[serde(default = "default_request_response_timeout")]
    request_response_timeout: DurationString,
}

enum ListenOnParseError {
    InvalidURL(InvalidURLError),
    PortMissing,
    PortOutOfBoundsError(u16),
    QueryStringUnsupported,
    CertificateFileRequired,
    KeyFileRequired,
    CertificateFileReadError(std::io::Error),
    KeyFileReadError(rustls::pki_types::pem::Error),
    SSLOptionsNotAllowed,
}

impl std::fmt::Display for ListenOnParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidURL(e) => {
                write!(f, "listen URL not valid: {e}")
            }
            Self::PortMissing => {
                write!(f, "port missing from listen URL")
            }
            Self::PortOutOfBoundsError(e) => {
                write!(f, "port in listen URL out of bounds: {e}")
            }
            Self::QueryStringUnsupported => {
                write!(f, "query strings may not be specified in listen URL")
            }
            Self::CertificateFileRequired => {
                write!(f, "certificate_file is required for HTTPS")
            }
            Self::KeyFileRequired => {
                write!(f, "key_file is required for HTTPS https")
            }
            Self::CertificateFileReadError(e) => {
                write!(f, "could not read certificate file: {e}")
            }
            Self::KeyFileReadError(e) => {
                write!(f, "could not read key file: {e}")
            }
            Self::SSLOptionsNotAllowed => {
                write!(
                    f,
                    "options certificate_file and key_file are not allowed when serving plain HTTP"
                )
            }
        }
    }
}

impl From<std::net::AddrParseError> for ListenOnParseError {
    fn from(err: std::net::AddrParseError) -> Self {
        ListenOnParseError::InvalidURL(InvalidURLError::AddrParseError(err))
    }
}

impl From<std::io::Error> for ListenOnParseError {
    fn from(err: std::io::Error) -> Self {
        ListenOnParseError::InvalidURL(InvalidURLError::AddrResolveError(err))
    }
}

impl TryFrom<ListenOn> for ListenerSpec {
    type Error = ListenOnParseError;

    fn try_from(other: ListenOn) -> Result<Self, Self::Error> {
        let hostport = format!(
            "{}:{}",
            match other.url.host() {
                Some(h) => h.to_string(),
                None => "0.0.0.0".to_string(),
            },
            match other.url.port() {
                Some(p) => {
                    if p < 1024 {
                        return Err(Self::Error::PortOutOfBoundsError(p));
                    }
                    p
                }
                None => {
                    return Err(Self::Error::PortMissing);
                }
            }
        );
        let Some(sockaddr) = hostport.to_socket_addrs()?.next() else {
            return Err(Self::Error::InvalidURL(
                InvalidURLError::InvalidAddressError(hostport),
            ));
        };

        if !other.url.username().is_empty() || other.url.password().is_some() {
            return Err(Self::Error::InvalidURL(
                InvalidURLError::AuthenticationUnsupported,
            ));
        }
        if other.url.query().is_some() {
            return Err(Self::Error::QueryStringUnsupported);
        }
        if other.url.fragment().is_some() {
            return Err(Self::Error::InvalidURL(
                InvalidURLError::FragmentUnsupported,
            ));
        }
        let proto = Protocol::try_from(&other)?;

        Ok(ListenerSpec {
            protocol: proto,
            sockaddr,
            handler: other.url.path().to_owned(),
            header_read_timeout: other.header_read_timeout.into(),
            request_response_timeout: other.request_response_timeout.into(),
        })
    }
}

fn default_timeout() -> DurationString {
    DurationString::new(Duration::new(30, 0))
}

#[derive(Debug, Deserialize, Clone)]
#[serde(remote = "Self")]
/// Indicates to the proxy which backend server to fetch metrics from.
pub struct ConnectTo {
    pub url: Url,
    #[serde(default = "bool::default")]
    pub tolerate_bad_tls: bool,
    #[serde(default = "default_timeout")]
    pub timeout: DurationString,
}

enum ConnectToParseError {
    InvalidURL(InvalidURLError),
}

impl std::fmt::Display for ConnectToParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidURL(e) => {
                write!(f, "connect URL not valid: {e}")
            }
        }
    }
}

impl<'de> Deserialize<'de> for ConnectTo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let other = ConnectTo::deserialize(deserializer)?;
        if !other.url.username().is_empty() || other.url.password().is_some() {
            return Err(serde::de::Error::custom(ConnectToParseError::InvalidURL(
                InvalidURLError::AuthenticationUnsupported,
            )));
        }
        if other.url.fragment().is_some() {
            return Err(serde::de::Error::custom(ConnectToParseError::InvalidURL(
                InvalidURLError::FragmentUnsupported,
            )));
        }
        let scheme = other.url.scheme();
        match scheme {
            "http" | "https" => {}
            _ => {
                return Err(serde::de::Error::custom(ConnectToParseError::InvalidURL(
                    InvalidURLError::UnsupportedScheme(scheme.to_owned()),
                )));
            }
        }

        Ok(other)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyEntry {
    listen_on: ListenerSpec,
    connect_to: ConnectTo,
    label_filters: Vec<LabelFilter>,
    #[serde(default = "default_cache_duration")]
    cache_duration: DurationString,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    proxies: Vec<ProxyEntry>,
    pub metrics: Option<ListenerSpec>,
}

#[derive(Debug)]
pub enum LoadError {
    ReadError(std::io::Error),
    ParseError(serde_yaml::Error),
    ConflictingConfig(String),
    InvalidActionRegex(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoadError::ReadError(e) => write!(f, "cannot read configuration: {e}"),
            LoadError::ParseError(e) => write!(f, "cannot parse configuration: {e}"),
            LoadError::ConflictingConfig(e) => write!(f, "conflicting configuration: {e}"),
            LoadError::InvalidActionRegex(e) => {
                write!(f, "invalid action regular expression: {e}")
            }
        }
    }
}

impl From<std::io::Error> for LoadError {
    fn from(err: std::io::Error) -> Self {
        LoadError::ReadError(err)
    }
}

impl From<serde_yaml::Error> for LoadError {
    fn from(err: serde_yaml::Error) -> Self {
        LoadError::ParseError(err)
    }
}

impl TryFrom<PathBuf> for Config {
    type Error = LoadError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        struct IndexAndProtocol {
            index: usize,
            protocol: Protocol,
        }
        let f = std::fs::File::open(path.clone())?;
        let maybecfg: Result<Config, serde_yaml::Error> = serde_yaml::from_reader(f);
        if let Err(error) = maybecfg {
            return Err(Self::Error::ParseError(error));
        }

        let cfg = maybecfg.unwrap();
        let mut by_host_port_handler = std::collections::HashMap::new();
        let mut by_host_port: HashMap<String, IndexAndProtocol> = std::collections::HashMap::new();
        for (index, element) in cfg.proxies.iter().enumerate() {
            let host_port_handler = format!(
                "{}/{}",
                element.listen_on.sockaddr, element.listen_on.handler
            );
            match by_host_port_handler.get(&host_port_handler) {
                Some(priorindex) => {
                    return Err(Self::Error::ConflictingConfig(format!(
                        "proxy {} in configuration proxies list contains the same host, port and handler as proxy {}; two proxies cannot listen on the same HTTP handler simultaneously",
                        priorindex + 1,
                        index + 1
                    )));
                }
                None => {
                    by_host_port_handler.insert(host_port_handler, index);
                }
            }

            let host_port = format!("{}", element.listen_on.sockaddr);
            match by_host_port.get(&host_port) {
                Some(prior) => {
                    if let Protocol::Https {
                        certificate: thiscert,
                        key: thiskey,
                    } = element.listen_on.protocol.clone()
                        && let Protocol::Https {
                            certificate: priorcert,
                            key: priorkey,
                        } = prior.protocol.clone()
                    {
                        if thiscert != priorcert {
                            return Err(Self::Error::ConflictingConfig(format!(
                                "proxy {} uses a different certificate from proxy {}; the same listening address must use the same certificate",
                                prior.index + 1,
                                index + 1
                            )));
                        }
                        if thiskey != priorkey {
                            return Err(Self::Error::ConflictingConfig(format!(
                                "proxy {} uses a different private key from proxy {}; the same listening address must use the same private key",
                                prior.index + 1,
                                index + 1
                            )));
                        }
                    }

                    if element.listen_on.protocol != prior.protocol {
                        return Err(Self::Error::ConflictingConfig(format!(
                            "proxy {} in configuration proxies list uses a protocol conflicting with proxy {} listening on the same host and port; the same listening address cannot serve both HTTP and HTTPS at the same time",
                            prior.index + 1,
                            index + 1
                        )));
                    }
                }
                None => {
                    by_host_port.insert(
                        host_port,
                        IndexAndProtocol {
                            index,
                            protocol: element.listen_on.protocol.clone(),
                        },
                    );
                }
            }
        }

        if let Some(telemetry) = &cfg.metrics
            && let Some(proxy) = by_host_port.get(&format!("{}", telemetry.sockaddr))
        {
            return Err(Self::Error::ConflictingConfig(format!(
                "telemetry configuration cannot reuse the host and port used by proxy {}",
                proxy.index + 1
            )));
        }

        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
pub struct HttpProxyTarget {
    pub connect_to: ConnectTo,
    pub label_filters: Vec<LabelFilter>,
    pub cache_duration: DurationString,
}

#[derive(Debug, Clone)]
pub struct HttpProxy {
    pub listen_on: ListenerSpec,
    pub handlers: HashMap<String, HttpProxyTarget>,
}

impl From<Config> for Vec<HttpProxy> {
    fn from(val: Config) -> Self {
        // This function is necessary because a config may specify multiple
        // listeners all on the same port and IP, each one with a different
        // proxy target, but the HTTP server cannot be told to listen to
        // the same host and port twice, so we have to group the configs
        // by listen port + listen IP.
        let mut servers: HashMap<String, HttpProxy> = HashMap::new();
        for proxy in val.proxies {
            let listen_on = proxy.listen_on;
            let serveraddr = format!("{}", listen_on.sockaddr);

            let newhandlers = HashMap::from([(
                listen_on.handler.clone(),
                HttpProxyTarget {
                    connect_to: proxy.connect_to,
                    label_filters: proxy.label_filters,
                    cache_duration: proxy.cache_duration,
                },
            )]);

            match servers.get(&serveraddr) {
                None => {
                    servers.insert(
                        serveraddr,
                        HttpProxy {
                            listen_on,
                            handlers: newhandlers,
                        },
                    );
                }
                Some(oldserver) => {
                    if !oldserver.handlers.contains_key(&listen_on.handler) {
                        servers.insert(
                            serveraddr,
                            HttpProxy {
                                listen_on: oldserver.listen_on.clone(),
                                handlers: oldserver
                                    .handlers
                                    .clone()
                                    .into_iter()
                                    .chain(newhandlers)
                                    .collect(),
                            },
                        );
                    }
                }
            }
        }
        servers.values().cloned().collect()
    }
}
