use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;

/// ConfigSource specifies source of a serialized configuration file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigSource {
    /// Use the hard-coded default configuration.
    Default,
    /// Read the config from stdin.
    StdIn,
    /// Use the literal string as the entire content of the config.
    Literal(String),
    /// Read the config from the specified file.
    File(PathBuf),
}

#[derive(Debug)]
pub enum ConfigError {
    /// An error occurred during config file I/O.
    IoError {
        source: ConfigSource,
        io_error: std::io::Error,
    },
    /// Failed to parse configuration.
    ParseError {
        source: ConfigSource,
        message: String,
    },
    /// Failed to validate configuration
    ValidationError {
        source: ConfigSource,
        message: String,
    },
}

/// Rules for validating the values of the Config struct
/// This prevents the Replica from being instantiated with
/// an invalid configuration
pub trait ConfigValidate: Sized {
    fn validate(self) -> Result<Self, String>;
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError { source, io_error } => {
                write!(f, "Failed to read config from {}: {}", source, io_error)
            }
            Self::ParseError { source, message } => {
                write!(f, "Failed to parse config from {}: {}", source, message)
            }
            Self::ValidationError { source, message } => {
                write!(f, "Failed to validate config from {}: {}", source, message)
            }
        }
    }
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::Default => write!(f, "Default"),
            ConfigSource::StdIn => write!(f, "<stdin>"),
            ConfigSource::Literal(s) => write!(f, "string '{}'", s),
            ConfigSource::File(path_buf) => write!(f, "file '{}'", path_buf.display()),
        }
    }
}

impl ConfigSource {
    /// Loads a value from the provided config source.
    /// The source is expected to be a valid JSON5 document.
    pub fn load<T: DeserializeOwned + Default + ConfigValidate>(&self) -> Result<T, ConfigError> {
        let cfg_str = match &self {
            ConfigSource::Default => return Ok(Default::default()),
            ConfigSource::Literal(literal) => literal.clone(),

            ConfigSource::StdIn => {
                use std::io::Read;

                let mut buf = String::new();

                std::io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|io_error| ConfigError::IoError {
                        source: self.clone(),
                        io_error,
                    })?;
                buf
            }

            ConfigSource::File(path) => {
                fs::read_to_string(&path).map_err(|io_error| ConfigError::IoError {
                    source: self.clone(),
                    io_error,
                })?
            }
        };

        let cfg = json5::from_str::<T>(&cfg_str).map_err(|err| ConfigError::ParseError {
            source: self.clone(),
            message: err.to_string(),
        })?;
        cfg.validate().map_err(|err| ConfigError::ValidationError {
            source: self.clone(),
            message: err,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(PartialEq, Debug, Default, Serialize, Deserialize)]
    struct KV {
        key: String,
        value: String,
    }

    impl ConfigValidate for KV {
        fn validate(self) -> Result<Self, String> {
            // Example validation function
            if !self.key.chars().all(char::is_alphabetic) {
                return Err(format!("field 'key' has invalid value ({})", self.key));
            }
            if self.value.is_empty() {
                return Err(format!("field 'value' has invalid value ({})", self.value));
            }
            Ok(self)
        }
    }

    #[test]
    fn can_parse_default() {
        assert_eq!(ConfigSource::Default.load::<KV>().unwrap(), KV::default());
    }

    #[test]
    fn can_parse_literal_string() {
        assert_eq!(
            ConfigSource::Literal(serialize_config(&test_config()))
                .load::<KV>()
                .unwrap(),
            test_config()
        );
    }

    #[test]
    fn can_read_config_from_file() {
        let s = serialize_config(&test_config());
        let tmp = tempfile::Builder::new()
            .prefix("config_parser")
            .tempdir()
            .unwrap();
        let path = tmp.path().join("ic.json5");
        std::fs::write(&path, s).unwrap();
        let config_src = ConfigSource::File(path);
        assert_eq!(config_src.load::<KV>().unwrap(), test_config());
    }

    fn serialize_config(kv: &KV) -> String {
        json5::to_string(kv).expect("Could not serialize to json5.")
    }

    fn test_config() -> KV {
        KV {
            key: "key".to_string(),
            value: "value".to_string(),
        }
    }
}
