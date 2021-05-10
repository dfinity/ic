#![allow(clippy::unwrap_used)]
use crate::tls_stub::cert_chain::{CspCertificateChain, CspCertificateChainCreationError};
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
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
    let cert = x509_cert();
    let certs = vec![cert.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq_certs(cert_chain.root(), &cert);
    assert_eq_certs(cert_chain.leaf(), &cert);
    assert_eq!(cert_chain.chain().len(), 1);
}

#[test]
fn should_return_correct_root_and_leaf_for_chain_with_two_entries() {
    let (root, leaf, _) = three_x509_certs();
    let certs = vec![root.clone(), leaf.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq_certs(cert_chain.root(), &root);
    assert_eq_certs(cert_chain.leaf(), &leaf);
    assert_eq!(cert_chain.chain().len(), 2);
}

#[test]
fn should_return_correct_root_and_leaf_for_chain_with_three_entries() {
    let (root, intermediate, leaf) = three_x509_certs();
    let certs = vec![root.clone(), intermediate.clone(), leaf.clone()];

    let cert_chain = CspCertificateChain::new(certs).unwrap();

    assert_eq_certs(cert_chain.root(), &root);
    assert_eq_certs(cert_chain.leaf(), &leaf);
    assert_eq_certs(cert_chain.chain().get(1).unwrap(), &intermediate);
    assert_eq!(cert_chain.chain().len(), 3);
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_single_entry() {
    let cert = x509_cert();
    let mut x509_stack = Stack::<X509>::new().unwrap();
    assert!(x509_stack.push(cert.clone()).is_ok());

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq_certs(cert_chain.root(), &cert);
    assert_eq_certs(cert_chain.leaf(), &cert);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_two_entries() {
    let (root, leaf, _) = three_x509_certs();
    let x509_stack = {
        let mut x509_stack = Stack::<X509>::new().unwrap();
        assert!(x509_stack.push(leaf.clone()).is_ok());
        assert!(x509_stack.push(root.clone()).is_ok());

        let mut x509_stack_iter = x509_stack.iter();
        assert_eq_cert_refs(x509_stack_iter.next().unwrap(), &leaf);
        assert_eq_cert_refs(x509_stack_iter.next().unwrap(), &root);
        assert!(x509_stack_iter.next().is_none());
        x509_stack
    };

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq_certs(cert_chain.root(), &root);
    assert_eq_certs(cert_chain.leaf(), &leaf);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_correctly_convert_from_x509_stackref_with_three_entries() {
    let (root, intermediate, leaf) = three_x509_certs();
    let x509_stack = {
        let mut x509_stack = Stack::<X509>::new().unwrap();
        assert!(x509_stack.push(leaf.clone()).is_ok());
        assert!(x509_stack.push(intermediate.clone()).is_ok());
        assert!(x509_stack.push(root.clone()).is_ok());

        let mut x509_stack_iter = x509_stack.iter();
        assert_eq_cert_refs(x509_stack_iter.next().unwrap(), &leaf);
        assert_eq_cert_refs(x509_stack_iter.next().unwrap(), &intermediate);
        assert_eq_cert_refs(x509_stack_iter.next().unwrap(), &root);
        assert!(x509_stack_iter.next().is_none());
        x509_stack
    };

    let cert_chain = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap();

    assert_eq_certs(cert_chain.root(), &root);
    assert_eq_certs(cert_chain.leaf(), &leaf);
    assert_eq_certs(cert_chain.chain().get(1).unwrap(), &intermediate);
    assert_eq!(x509_stack.len(), cert_chain.chain().len());
}

#[test]
fn should_fail_to_convert_from_x509_stackref_if_empty() {
    let x509_stack = Stack::<X509>::new().unwrap();

    let err = CspCertificateChain::try_from(x509_stack.as_ref()).unwrap_err();

    assert_eq!(err, CspCertificateChainCreationError::ChainEmpty);
}

fn x509_cert() -> X509 {
    CertWithPrivateKey::builder()
        .cn(format!("{}", thread_rng().gen::<u64>()))
        .build_ed25519()
        .x509()
}

fn three_x509_certs() -> (X509, X509, X509) {
    let c1 = x509_cert();
    let c2 = x509_cert();
    let c3 = x509_cert();
    assert_ne_certs(&c1, &c2);
    assert_ne_certs(&c1, &c3);
    assert_ne_certs(&c2, &c3);
    (c1, c2, c3)
}

fn assert_eq_certs(c1: &X509, c2: &X509) {
    let c1_der = c1.to_der().expect("failed to encode as DER");
    let c2_der = c2.to_der().expect("failed to encode as DER");
    assert_eq!(c1_der, c2_der);
}

fn assert_eq_cert_refs(c1: &X509Ref, c2: &X509Ref) {
    let c1_der = c1.to_der().expect("failed to encode as DER");
    let c2_der = c2.to_der().expect("failed to encode as DER");
    assert_eq!(c1_der, c2_der);
}

fn assert_ne_certs(c1: &X509, c2: &X509) {
    let c1_der = c1.to_der().expect("failed to encode as DER");
    let c2_der = c2.to_der().expect("failed to encode as DER");
    assert_ne!(c1_der, c2_der);
}
