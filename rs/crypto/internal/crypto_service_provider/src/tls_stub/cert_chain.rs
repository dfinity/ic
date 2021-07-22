//! X.509 certificate chain utilities

use super::*;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use openssl::stack::StackRef;
use openssl::x509::X509;
use std::fmt::{self, Debug, Formatter};

#[cfg(test)]
mod tests;

/// A non-empty list of certificates representing a certificate chain.
///
/// The container provides no guarantees as to whether the certificates actually
/// form a chain in terms of issuance. It is the callers responsibility to
/// ensure this upon instantiation.
///
/// The container provides convenience methods to access the chain's root and
/// leaf. If the chain contains only a single element, this element is both the
/// root and the leaf.
#[derive(Clone)]
pub struct CspCertificateChain {
    /// The first element is considered the chain's root
    chain: Vec<TlsPublicKeyCert>,
}

impl CspCertificateChain {
    /// Creates a new certificate chain.
    ///
    /// The first element in the `chain` is considered the `root`. The last
    /// element is considered the `leaf`. It is the callers responsibility to
    /// ensure that the certificates actually form a chain in terms of
    /// issuance.
    ///
    /// Returns an error if the given `chain` is empty.
    fn new(chain: Vec<TlsPublicKeyCert>) -> Result<Self, CspCertificateChainCreationError> {
        if chain.is_empty() {
            return Err(CspCertificateChainCreationError::ChainEmpty);
        }
        Ok(Self { chain })
    }

    /// Returns the chain as vector where the root is the first element.
    pub fn chain(&self) -> &Vec<TlsPublicKeyCert> {
        &self.chain
    }

    /// Returns the root of the chain.
    pub fn root(&self) -> &TlsPublicKeyCert {
        &self
            .chain
            .get(Self::root_index())
            .expect("invariant violated: chain is empty")
    }

    /// Returns the leaf of the chain.
    pub fn leaf(&self) -> &TlsPublicKeyCert {
        &self
            .chain
            .get(self.leaf_index())
            .expect("invariant violated: chain is empty")
    }

    fn root_index() -> usize {
        0
    }

    fn leaf_index(&self) -> usize {
        self.chain.len() - 1
    }
}

/// An error indicating that a certificate chain could not be created
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspCertificateChainCreationError {
    ChainEmpty,
    CertificateMalformed { internal_error: String },
}

impl TryFrom<&StackRef<X509>> for CspCertificateChain {
    type Error = CspCertificateChainCreationError;

    /// Perform the conversion assuming that the stack's iterator first returns
    /// the leaf certificate of the chain that is represented by the stack.
    fn try_from(x509_stack: &StackRef<X509>) -> Result<Self, Self::Error> {
        let mut chain = Vec::new();
        for x509 in x509_stack.iter().rev() {
            let cert = TlsPublicKeyCert::new_from_x509(x509.to_owned()).map_err(|e| {
                CspCertificateChainCreationError::CertificateMalformed {
                    internal_error: e.internal_error,
                }
            })?;
            chain.push(cert);
        }
        Self::new(chain)
    }
}

impl fmt::Debug for CspCertificateChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let root_idx = CspCertificateChain::root_index();
        match self.chain.len() {
            0 => panic!("invariant violated: chain is empty"),
            1 => {
                writeln!(f, "root=leaf: {:?}, ", self.chain.get(root_idx).to_owned())?;
            }
            _ => {
                writeln!(f, "Start of certificate chain")?;
                for (i, cert) in self.chain.iter().enumerate() {
                    write!(f, "├─")?;
                    if i == root_idx {
                        write!(f, " root: ")?;
                    }
                    if i == self.leaf_index() {
                        write!(f, " leaf: ")?;
                    }
                    writeln!(f, "{:?}", cert.to_owned())?;
                }
                writeln!(f, "End of certificate chain")?;
            }
        }
        Ok(())
    }
}
