use std::time::Duration;

use anyhow::{bail, Error};
use mockall::predicate;
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair};

use crate::tls::{
    extract_cert_validity, LoadError, MockLoad, MockProvision, MockStore, Provision,
    ProvisionResult, WithLoad, WithStore,
};

use super::TLSCert;

fn generate_certificate_chain(
    name: &str,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> Result<Vec<u8>, Error> {
    // Root
    let root_key_pair = KeyPair::generate()?;
    let root_cert = CertificateParams::new(vec![
        "root.example.com".into(), // SAN
    ])?
    .self_signed(&root_key_pair)?;

    // Intermediate
    let intermediate_key_pair = KeyPair::generate()?;
    let intermediate_cert = CertificateParams::new(vec![
        "intermediate.example.com".into(), // SAN
    ])?
    .self_signed(&intermediate_key_pair)?;

    // Leaf
    let leaf_key_pair = KeyPair::generate()?;
    let leaf_cert = {
        let mut params = CertificateParams::new(vec![
            name.into(), // SAN
        ])?;

        // Set common name
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::PrintableString(name.try_into()?),
        );
        params.distinguished_name = dn;

        // Set validity
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);

        params.self_signed(&leaf_key_pair)?
    };

    Ok([
        root_cert.pem().into_bytes(),
        intermediate_cert.pem().into_bytes(),
        leaf_cert.pem().into_bytes(),
    ]
    .concat())
}

#[tokio::test]
async fn extract_cert_validity_found_test() -> Result<(), Error> {
    // Create a certificate
    let not_before = (2000, 1, 1);
    let not_after = (2001, 1, 1);

    let cert_chain = generate_certificate_chain(
        "leaf-1.example.com", // name
        not_before,           // not_before
        not_after,            // not_after
    )?;

    // Extract validity
    let v = extract_cert_validity(
        "leaf-1.example.com", // name
        &cert_chain,          // cert_chain
    )?
    .expect("validity not found");

    let not_before =
        rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2).unix_timestamp();

    let not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2).unix_timestamp();

    assert_eq!(not_before, v.not_before.timestamp());
    assert_eq!(not_after, v.not_after.timestamp());

    Ok(())
}

#[tokio::test]
async fn extract_cert_validity_not_found_test() -> Result<(), Error> {
    // Create a certificate
    let not_before = (2000, 1, 1);
    let not_after = (2001, 1, 1);

    let cert_chain = generate_certificate_chain(
        "leaf-1.example.com", // name
        not_before,           // not_before
        not_after,            // not_after
    )?;

    // Extract validity
    let v = extract_cert_validity(
        "leaf-2.example.com", // name
        &cert_chain,          // cert_chain
    )?;

    if v.is_some() {
        bail!("expected certificate to not be found");
    }

    Ok(())
}

#[tokio::test]
async fn with_load_not_found_test() -> Result<(), Error> {
    let mut p = MockProvision::new();
    p.expect_provision()
        .times(1)
        .with(predicate::eq("example.com"))
        .returning(|_| {
            Ok(ProvisionResult::Issued(TLSCert(
                "cert".into(),
                "pkey".into(),
            )))
        });

    let mut l = MockLoad::new();
    l.expect_load()
        .times(1)
        .returning(|| Err(LoadError::NotFound));

    let mut p = WithLoad(
        p,                      // provisioner
        l,                      // loader
        Duration::from_secs(1), // remaining cert validity
    );

    let out = p.provision("example.com").await?;
    assert_eq!(
        out,
        ProvisionResult::Issued(TLSCert("cert".into(), "pkey".into()))
    );

    Ok(())
}

#[tokio::test]
async fn with_load_expired_test() -> Result<(), Error> {
    // Generate expired certificate
    let not_before = (2000, 1, 1);
    let not_after = (2001, 1, 1);

    let cert_chain = generate_certificate_chain(
        "example.com", // name
        not_before,    // not_before
        not_after,     // not_after
    )?;
    let cert_chain = String::from_utf8(cert_chain)?;

    let mut p = MockProvision::new();
    p.expect_provision()
        .times(1)
        .with(predicate::eq("example.com"))
        .returning(|_| {
            Ok(ProvisionResult::Issued(TLSCert(
                "cert".into(),
                "pkey".into(),
            )))
        });

    let mut l = MockLoad::new();
    l.expect_load()
        .times(1)
        .returning(move || Ok(TLSCert(cert_chain.clone(), "pkey".into())));

    let mut p = WithLoad(
        p,                      // provisioner
        l,                      // loader
        Duration::from_secs(1), // remaining cert validity
    );

    let out = p.provision("example.com").await?;
    assert_eq!(
        out,
        ProvisionResult::Issued(TLSCert("cert".into(), "pkey".into()))
    );

    Ok(())
}

#[tokio::test]
async fn with_load_valid_test() -> Result<(), Error> {
    // Generate expired certificate
    let not_before = (2000, 1, 1);
    let not_after = (3000, 1, 1);

    let cert_chain = generate_certificate_chain(
        "example.com", // name
        not_before,    // not_before
        not_after,     // not_after
    )?;
    let cert_chain = String::from_utf8(cert_chain)?;

    let mut p = MockProvision::new();
    p.expect_provision().times(0);

    let mut l = MockLoad::new();

    let cert_chain_cpy = cert_chain.clone();
    l.expect_load()
        .times(1)
        .returning(move || Ok(TLSCert(cert_chain_cpy.clone(), "pkey".into())));

    let mut p = WithLoad(
        p,                      // provisioner
        l,                      // loader
        Duration::from_secs(1), // remaining cert validity
    );

    let out = p.provision("example.com").await?;
    assert_eq!(
        out,
        ProvisionResult::StillValid(TLSCert(cert_chain, "pkey".into()))
    );

    Ok(())
}

#[tokio::test]
async fn with_store_test() -> Result<(), Error> {
    let mut p = MockProvision::new();
    p.expect_provision()
        .times(1)
        .with(predicate::eq("example.com"))
        .returning(|_| {
            Ok(ProvisionResult::Issued(TLSCert(
                "cert".into(),
                "pkey".into(),
            )))
        });

    let mut s = MockStore::new();
    s.expect_store()
        .times(1)
        .with(predicate::eq(TLSCert("cert".into(), "pkey".into())))
        .returning(|_| Ok(()));

    let mut p = WithStore(p, s);

    let out = p.provision("example.com").await?;
    assert_eq!(
        out,
        ProvisionResult::Issued(TLSCert("cert".into(), "pkey".into()))
    );

    Ok(())
}
