//! The dev root CA: the certificate authority that every *dev* IC-OS image
//! already trusts.
//!
//! Shared by the two things that care about it: the local backend, which puts it
//! in the driver's own trust store (`LocalBackend::install_dev_root_ca`), and the
//! IC gateway, which issues its TLS leaf from it
//! (`IcGatewayVm::load_or_create_local_playnet`). It lives in its own module
//! rather than in either of those because it belongs to neither — what trusts it
//! is the IC-OS images.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::EncodePrivateKey};
use std::fs;

use crate::driver::test_env_api::get_dependency_path_from_env;

/// The dev root CA, loaded ready to sign with.
///
/// `ic-os/{guestos,hostos}/context/Dockerfile` installs
/// `ic-os/components/networking/dev-certs/canister_http_test_ca.cert` into
/// `/usr/local/share/ca-certificates` and runs `update-ca-certificates` — in the
/// `output_dev` stage only, so a production image trusts nothing extra. Its
/// private key is checked in beside it, which is how a test can serve HTTPS that
/// a node accepts without any node-side configuration; `canister_http` and
/// `ckbtc` already rely on this, and its `README.md` documents the use.
///
/// The certificate and the key reach us as runfiles, provided to the local
/// backend's variant of every system test by `_local_only_deps` in
/// `rs/tests/system_tests.bzl`. Reading either on the Farm backend would panic,
/// and must not happen: Farm uses a playnet certificate.
pub(crate) struct DevRootCa {
    /// PEM of the checked-in CA certificate, exactly as it sits in the images'
    /// trust store. This is what the gateway serves as its chain.
    pub(crate) cert_pem: String,
    /// The same CA as an `rcgen` issuer.
    pub(crate) cert: rcgen::Certificate,
    pub(crate) key: KeyPair,
}

/// The PEM of the dev root CA certificate. See [`DevRootCa`].
pub(crate) fn dev_root_ca_cert_pem() -> Result<String> {
    let path = get_dependency_path_from_env("ENV_DEPS__DEV_ROOT_CA_CERT_PATH");
    fs::read_to_string(&path).with_context(|| {
        format!(
            "reading the dev root CA certificate from {}",
            path.display()
        )
    })
}

/// Loads the dev root CA so `rcgen` can issue certificates from it.
pub(crate) fn dev_root_ca() -> Result<DevRootCa> {
    let cert_pem = dev_root_ca_cert_pem()?;
    let key_path = get_dependency_path_from_env("ENV_DEPS__DEV_ROOT_CA_KEY_PATH");
    let key_pkcs1_pem = fs::read_to_string(&key_path)
        .with_context(|| format!("reading the dev root CA key from {}", key_path.display()))?;

    // The checked-in key is PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`), which
    // `rcgen` loads only under its `aws_lc_rs` backend; under `ring` it takes
    // PKCS#8 only. Which of the two is compiled in is not ours to decide: both
    // features are on, and `rcgen` prefers `aws_lc_rs` when they are — but only
    // because `rustls-acme` happens to enable it, four crates away (see
    // `cargo tree -i rcgen -e features`). Re-encoding to PKCS#8 works under either
    // backend, so it does not matter if that ever changes; relying on the feature
    // would turn an unrelated dependency edit into a runtime failure in every
    // local gateway test.
    let key_pkcs8_pem = RsaPrivateKey::from_pkcs1_pem(&key_pkcs1_pem)
        .context("parsing the dev root CA key as PKCS#1")?
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .context("re-encoding the dev root CA key as PKCS#8")?;
    let key = KeyPair::from_pem(&key_pkcs8_pem).context("loading the dev root CA key")?;

    // `from_ca_cert_pem` extracts what is needed to act as an issuer, of which
    // `signed_by` uses one thing: the subject name, which becomes the leaf's
    // issuer. (It carries the CA's subject key identifier across too, but that
    // reaches the leaf as an authority key identifier only when
    // `use_authority_key_identifier_extension` is set, and `CertificateParams::new`
    // leaves it false — the leaf's only extension is its SAN.) `self_signed` then
    // re-signs the CA merely to obtain an `rcgen::Certificate` to pass as that
    // issuer; the result is not the checked-in certificate byte for byte and is
    // never served. What makes the chain verify is the issuer name plus the
    // signature, both of which are the real CA's.
    let cert = CertificateParams::from_ca_cert_pem(&cert_pem)
        .context("parsing the dev root CA certificate")?
        .self_signed(&key)
        .context("loading the dev root CA certificate as an issuer")?;

    Ok(DevRootCa {
        cert_pem,
        cert,
        key,
    })
}
