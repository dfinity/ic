use super::*;

use std::{str::FromStr, time::Duration};

use anyhow::Error;
use ic_types::{NodeId, PrincipalId};
use rustls::{
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, Error as RustlsError,
};

use crate::{
    snapshot::{Snapshot, Snapshotter},
    test_utils::{create_fake_registry_client, valid_tls_certificate_and_validation_time},
};

// CN = s52il-lowsg-eip4y-pt5lv-sbdpb-vg4gg-4iasu-egajp-yluji-znfz3-2qe
const TEST_CERTIFICATE: &str = "3082015530820107a00302010202136abf05c1260364e09ad5f4ad0e9cb90a6e0edb300506032b6570304a3148304606035504030c3f733532696c2d6c6f7773672d\
                                65697034792d7074356c762d73626470622d76673467672d34696173752d6567616a702d796c756a692d7a6e667a332d3271653020170d3232313131343135303230\
                                345a180f39393939313233313233353935395a304a3148304606035504030c3f733532696c2d6c6f7773672d65697034792d7074356c762d73626470622d76673467\
                                672d34696173752d6567616a702d796c756a692d7a6e667a332d327165302a300506032b65700321002b5c5af2776114a400d71995cf9cdb72ca1a26b59b875a3d70\
                                c79bf48b5f210b300506032b6570034100f3ded920aa535295c69fd97c8da2d73ce525370456cdaacc4863b25e19b0d2af1961454ac5ff9a9e182ea54034ceed0dd0\
                                2a7bd9421ae1f844c894544bca9602";

fn test_certificate() -> Vec<u8> {
    hex::decode(TEST_CERTIFICATE).unwrap()
}

fn check_certificate_verification(
    tls_verifier: &TlsVerifier,
    name: &str,
    der: Vec<u8>,
) -> Result<(), RustlsError> {
    let crt = CertificateDer::from(der);
    let intermediates: Vec<CertificateDer> = vec![];
    let server_name = ServerName::try_from(name).unwrap();
    let ocsp_response: Vec<u8> = vec![];

    tls_verifier.verify_server_cert(
        &crt,
        intermediates.as_slice(),
        &server_name,
        ocsp_response.as_slice(),
        UnixTime::now(),
    )?;

    Ok(())
}

#[tokio::test]
async fn test_verify_tls_certificate() -> Result<(), Error> {
    let snapshot = Arc::new(ArcSwapOption::empty());

    // Same node_id that valid_tls_certificate_and_validation_time() is valid for
    let node_id = NodeId::from(
        PrincipalId::from_str("4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae")
            .unwrap(),
    );

    let (reg, _, _) = create_fake_registry_client(1, 1, Some(node_id));
    let reg = Arc::new(reg);
    let (channel_send, _) = tokio::sync::watch::channel(None);
    let mut snapshotter =
        Snapshotter::new(Arc::clone(&snapshot), channel_send, reg, Duration::ZERO);
    let verifier = TlsVerifier::new(Arc::clone(&snapshot), false);
    snapshotter.snapshot()?;

    let snapshot = snapshot.load_full().unwrap();
    let node_name = snapshot.subnets[0].nodes[0].id.to_string();

    // Check valid certificate
    check_certificate_verification(
        &verifier,
        node_name.as_str(),
        valid_tls_certificate_and_validation_time()
            .0
            .certificate_der,
    )?;

    // Check with different cert -> should fail
    let r = check_certificate_verification(&verifier, node_name.as_str(), test_certificate());
    matches!(
        r,
        Err(RustlsError::InvalidCertificate(
            CertificateError::NotValidForName
        ))
    );

    // Check different DnsName -> should fail
    let r = check_certificate_verification(
        &verifier,
        "blah-blah-foo-bar",
        valid_tls_certificate_and_validation_time()
            .0
            .certificate_der,
    );
    matches!(
        r,
        Err(RustlsError::InvalidCertificate(
            CertificateError::NotValidForName
        ))
    );

    Ok(())
}
