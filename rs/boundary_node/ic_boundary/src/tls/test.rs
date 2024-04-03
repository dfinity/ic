use std::time::Duration;

use anyhow::{bail, Error};
use mockall::predicate;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, DnValue};
use tempfile::NamedTempFile;

use crate::tls::{
    extract_cert_validity, LoadError, MockLoad, MockProvision, MockStore, Provision,
    ProvisionResult, WithLoad, WithStore,
};

use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{load_or_create_acme_account, TLSCert};

fn generate_certificate_chain(
    name: &str,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> Result<Vec<u8>, Error> {
    // Root
    let root_cert = Certificate::from_params(CertificateParams::new(vec![
        "root.example.com".into(), // SAN
    ]))?;

    // Intermediate
    let intermediate_cert = Certificate::from_params(CertificateParams::new(vec![
        "intermediate.example.com".into(), // SAN
    ]))?;

    // Leaf
    let leaf_cert = Certificate::from_params({
        let mut params = CertificateParams::new(vec![
            name.into(), // SAN
        ]);

        // Set common name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::PrintableString(name.into()));
        params.distinguished_name = dn;

        // Set validity
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);

        params
    })?;

    Ok([
        root_cert.serialize_pem()?.into_bytes(),
        intermediate_cert.serialize_pem()?.into_bytes(),
        leaf_cert.serialize_pem()?.into_bytes(),
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

// False positive dead_code warning.
// It doesn't recognize the Drop implementation of its fields.
// See https://github.com/rust-lang/rust/issues/122833.
struct AcmeProviderGuard(#[allow(dead_code)] MockServer);

async fn create_acme_provider() -> Result<(AcmeProviderGuard, String), Error> {
    let mock_server = MockServer::start().await;

    // Directory
    let mock_server_url = mock_server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{
            "newAccount": "{mock_server_url}/new-acct",
            "newNonce": "{mock_server_url}/new-nonce",
            "newOrder": "{mock_server_url}/new-order"
        }}"#,
        )))
        .mount(&mock_server)
        .await;

    // Nonce
    Mock::given(method("HEAD"))
        .and(path("/new-nonce"))
        .respond_with(ResponseTemplate::new(200).append_header(
            "replay-nonce", // key
            "nonce",        // value
        ))
        .mount(&mock_server)
        .await;

    // Account
    Mock::given(method("POST"))
        .and(path("/new-acct"))
        .respond_with(ResponseTemplate::new(200).append_header(
            "Location",   // key
            "account-id", // value
        ))
        .mount(&mock_server)
        .await;

    let acme_provider_url = format!("{}/directory", mock_server_url);

    Ok((
        AcmeProviderGuard(mock_server), // guard
        acme_provider_url,              // acme_provider_url
    ))
}

#[tokio::test]
async fn load_or_create_acme_account_test() -> Result<(), Error> {
    // Spin-up a mocked ACME provider
    let (_guard, acme_provider_url) = create_acme_provider().await?;

    // Get a temporary file path
    let f = NamedTempFile::new()?;
    let p = f.path().to_path_buf();
    drop(f);

    // Create an account
    let account = load_or_create_acme_account(
        &p,                             // path
        &acme_provider_url,             // acme_provider_url
        Box::new(hyper::Client::new()), // http_client
    )
    .await?;

    // Serialize the credentials for later comparison
    let creds = serde_json::to_string(&account.credentials())?;

    // Reload the account
    let account = load_or_create_acme_account(
        &p,                             // path
        &acme_provider_url,             // acme_provider_url
        Box::new(hyper::Client::new()), // http_client
    )
    .await?;

    assert_eq!(
        creds,                                          // previous
        serde_json::to_string(&account.credentials())?, // current
    );

    // Clean up
    std::fs::remove_file(&p)?;

    Ok(())
}
