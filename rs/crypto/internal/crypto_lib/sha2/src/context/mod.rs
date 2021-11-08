//! Domain separation context types for hashing.
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

/// A domain separation context that can be represented as bytes.
pub trait Context {
    fn as_bytes(&self) -> &[u8];
}

/// A domain separation context based on a `String` to separate domains when
/// hashing.
pub struct DomainSeparationContext {
    domain: String,
    bytes: Vec<u8>,
}

impl DomainSeparationContext {
    /// Returns a new domain separation context.
    ///
    /// The byte representation of the context is a concatenation of
    /// * one byte indicating the length of the domain's UTF-8 bytes
    /// * the domain's UTF-8 bytes
    ///
    /// Panics if the length of the domain's UTF-8 bytes is too long to fit into
    /// one byte (that is, greater than 255).
    pub fn new<S: Into<String>>(domain: S) -> DomainSeparationContext {
        let domain: String = domain.into();

        let domain_bytes: &[u8] = domain.as_bytes();
        let domain_bytes_len = u8::try_from(domain_bytes.len()).expect("domain too long");

        let mut bytes = vec![domain_bytes_len];
        bytes.extend(domain_bytes);

        DomainSeparationContext { domain, bytes }
    }

    /// Returns the domain as string.
    #[allow(dead_code)]
    pub fn domain(&self) -> &String {
        &self.domain
    }
}

impl fmt::Debug for DomainSeparationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DomainSeparationContext{{ domain: \"{}\" }}",
            &self.domain
        )
    }
}

impl Context for DomainSeparationContext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
