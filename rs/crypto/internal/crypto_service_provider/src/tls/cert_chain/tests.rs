#![allow(clippy::unwrap_used)]
use crate::tls::cert_chain::{CspCertificateChain, CspCertificateChainCreationError};
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use openssl::stack::Stack;
use openssl::x509::{X509Ref, X509};
use rand::thread_rng;
use rand::Rng;
use std::convert::TryFrom;

#[test]
fn should_fail_to_create_empty_chain() {
    let err = CspCertificateChain::new(vec![]).unwrap_err();

    assert_eq!(err, CspCertificateChainCreationError::ChainEmpty);
}

#[test]
fn should_return_correct_root_and_leaf_for_chain_with_single_entry() {
    let cert = tls_cert();
    let certs = vec![cert.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq!(cert_chain.root(), &cert);
    assert_eq!(cert_chain.leaf(), &cert);
    assert_eq!(cert_chain.chain().len(), 1);
}

#[test]
fn should_return_correct_root_and_leaf_for_chain_with_two_entries() {
    let (root, leaf, _) = three_tls_certs();
    let certs = vec![root.clone(), leaf.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq!(cert_chain.root(), &root);
    assert_eq!(cert_chain.leaf(), &leaf);
    assert_eq!(cert_chain.chain().len(), 2);
}

#[test]
fn should_return_correct_root_and_leaf_for_chain_with_three_entries() {
    let (root, intermediate, leaf) = three_tls_certs();
    let certs = vec![root.clone(), intermediate.clone(), leaf.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq!(cert_chain.root(), &root);
    assert_eq!(cert_chain.leaf(), &leaf);
    assert_eq!(cert_chain.chain().get(1).unwrap(), &intermediate);
    assert_eq!(cert_chain.chain().len(), 3);
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_single_entry() {
    let cert = tls_cert();
    let mut x509_stack = Stack::<X509>::new().unwrap();
    assert!(x509_stack.push(cert.as_x509().clone()).is_ok());

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq!(cert_chain.root(), &cert);
    assert_eq!(cert_chain.leaf(), &cert);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_two_entries() {
    let (root, leaf, _) = three_tls_certs();
    let x509_stack = {
        let mut x509_stack = Stack::<X509>::new().unwrap();
        assert!(x509_stack.push(leaf.as_x509().clone()).is_ok());
        assert!(x509_stack.push(root.as_x509().clone()).is_ok());

        let mut x509_stack_iter = x509_stack.iter();
        assert_eq_x509ref_tls(x509_stack_iter.next().unwrap(), &leaf);
        assert_eq_x509ref_tls(x509_stack_iter.next().unwrap(), &root);
        assert!(x509_stack_iter.next().is_none());
        x509_stack
    };

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq!(cert_chain.root(), &root);
    assert_eq!(cert_chain.leaf(), &leaf);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_three_entries() {
    let (root, intermediate, leaf) = three_tls_certs();
    let x509_stack = {
        let mut x509_stack = Stack::<X509>::new().unwrap();
        assert!(x509_stack.push(leaf.as_x509().clone()).is_ok());
        assert!(x509_stack.push(intermediate.as_x509().clone()).is_ok());
        assert!(x509_stack.push(root.as_x509().clone()).is_ok());

        let mut x509_stack_iter = x509_stack.iter();
        assert_eq_x509ref_tls(x509_stack_iter.next().unwrap(), &leaf);
        assert_eq_x509ref_tls(x509_stack_iter.next().unwrap(), &intermediate);
        assert_eq_x509ref_tls(x509_stack_iter.next().unwrap(), &root);
        assert!(x509_stack_iter.next().is_none());
        x509_stack
    };

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq!(cert_chain.root(), &root);
    assert_eq!(cert_chain.leaf(), &leaf);
    assert_eq!(cert_chain.chain().get(1).unwrap(), &intermediate);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_fail_to_convert_from_x509_stackref_if_empty() {
    let x509_stack = Stack::<X509>::new().unwrap();

    let err = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap_err();

    assert_eq!(err, CspCertificateChainCreationError::ChainEmpty);
}

fn assert_eq_x509ref_tls(c1: &X509Ref, c2: &TlsPublicKeyCert) {
    let c1 = TlsPublicKeyCert::new_from_x509(c1.to_owned())
        .expect("Failed to convert X509 to TlsPublicKeyCert");
    assert_eq!(&c1, c2);
}

fn tls_cert() -> TlsPublicKeyCert {
    let x509 = CertWithPrivateKey::builder()
        .cn(format!("{}", thread_rng().gen::<u64>()))
        .build_ed25519()
        .x509();
    TlsPublicKeyCert::new_from_x509(x509).expect("Failed to create TlsPublicKeyCert")
}

fn three_tls_certs() -> (TlsPublicKeyCert, TlsPublicKeyCert, TlsPublicKeyCert) {
    let c1 = tls_cert();
    let c2 = tls_cert();
    let c3 = tls_cert();
    assert_ne!(&c1, &c2);
    assert_ne!(&c1, &c3);
    assert_ne!(&c2, &c3);
    (c1, c2, c3)
}
