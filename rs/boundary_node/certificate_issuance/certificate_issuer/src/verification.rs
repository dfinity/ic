use std::{sync::Arc, time::SystemTime};

use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use candid::{Encode, Principal};
use certificate_orchestrator_interface::{LABEL_DOMAINS, LEFT_GUARD, RIGHT_GUARD};
use ic_agent::{
    Agent, Certificate,
    hash_tree::{HashTree, HashTreeNode, LookupResult},
    lookup_value,
};
use sha2::{Digest, Sha256};

use crate::certificate::Package;

const ALLOWED_CERTIFICATE_TIME_OFFSET_NS: u128 = 300_000_000_000;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Verify: Sync + Send {
    async fn verify(
        &self,
        key: Option<String>,
        limit: u64,
        pkgs: &[Package],
        cert: &Certificate,
        tree: &HashTree<Vec<u8>>,
    ) -> Result<(), VerifyError>;
}

pub struct CertificateVerifier {
    agent: Arc<Agent>,
    canister_id: Principal,
}

impl CertificateVerifier {
    pub fn new(agent: Arc<Agent>, canister_id: Principal) -> Self {
        Self { agent, canister_id }
    }
}

#[async_trait]
impl Verify for CertificateVerifier {
    async fn verify(
        &self,
        key: Option<String>,
        limit: u64,
        pkgs: &[Package],
        cert: &Certificate,
        tree: &HashTree<Vec<u8>>,
    ) -> Result<(), VerifyError> {
        // Check certificate time
        let mut encoded_certificate_time = match cert.tree.lookup_path(["time".as_bytes()]) {
            LookupResult::Found(encoded_certificate_time) => Ok(encoded_certificate_time),
            _ => Err(anyhow!("failed to lookup time path in certificate")),
        }?;

        let certificate_time = leb128::read::unsigned(&mut encoded_certificate_time)
            .context("failed to read leb128-formatted time")?
            as u128;

        let current_time_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("failed to get unix timestamp")?
            .as_nanos();

        if certificate_time > current_time_ns + ALLOWED_CERTIFICATE_TIME_OFFSET_NS {
            return Err(anyhow!("certificate time too far in the future").into());
        }

        if certificate_time < current_time_ns - ALLOWED_CERTIFICATE_TIME_OFFSET_NS {
            return Err(anyhow!("certificate time too far in the past").into());
        }

        // Check the shared part of validation
        validate_shared(
            cert,             // cert
            tree,             // tree
            &self.agent,      // agent
            self.canister_id, // canister_id
        )
        .context("failed to validate shared")?;

        // Check that: (exactly one id <= key) xor (left guard is included in the certificate, no id <= key)
        let left_guard_present = validate_package(tree, LEFT_GUARD, &Vec::new()).is_ok();

        if key.is_none() && !left_guard_present {
            return Err(anyhow!("missing left guard on left-most page (key is none)").into());
        }

        if let Some(key) = key {
            // When key is provided and response is empty, require that left guard is present
            if pkgs.is_empty() && !left_guard_present {
                return Err(anyhow!("missing left guard on empty page").into());
            }

            // When a key is provided, require that the first item ID is <= the given key
            // or that a left guard is present
            if let Some(pkg) = pkgs.first()
                && pkg.id > key
                && !left_guard_present
            {
                return Err(anyhow!("first item greater than key").into());
            }

            // When a key is provided, require that only the first item ID is <= the given key
            if let Some(pkg) = pkgs.get(1)
                && pkg.id <= key
            {
                return Err(anyhow!("second item lower/equal than key").into());
            }
        }

        // Check right guard
        let right_guard_present = validate_package(tree, RIGHT_GUARD, &Vec::new()).is_ok();

        // When pkgs are less than limit, require a right guard
        if pkgs.len() < (limit as usize) && !right_guard_present {
            return Err(anyhow!("missing right guard").into());
        }

        // Ensure package IDs are in ascending sorted order
        if !pkgs.windows(2).all(|pair| pair[0].id < pair[1].id) {
            return Err(anyhow!("packages are not sorted in ascending order").into());
        }

        // Ensure all packages pass verification
        for pkg in pkgs {
            validate_package(
                tree,                                                // tree
                &pkg.id,                                             // key
                &Encode!(&pkg).context("failed to encode package")?, // val
            )
            .context("package failed validation")?;
        }

        // Verify that no leaves were pruned in the provided hash tree
        let bool_vector = indicator_vector(tree.as_ref());

        // How many leaves are expected to be in the tree
        let mut number_of_leaves = pkgs.len();

        // If we got fewer packages than the limit, the right guard should also be in the tree
        if number_of_leaves < limit as usize {
            number_of_leaves += 1;
        };

        // Is left guard also in the tree?
        if left_guard_present {
            number_of_leaves += 1;
        };

        if bool_vector.iter().filter(|&n| *n).count() != number_of_leaves {
            return Err(anyhow!("wrong number of leaves").into());
        }

        if bool_vector
            .iter()
            .skip_while(|&b| !*b)
            .skip_while(|&b| *b)
            .any(|b| *b)
        {
            return Err(anyhow!("certificate tree is pruned incorrectly").into());
        }

        Ok(())
    }
}

// Check the IC signature and the shared part of verification
fn validate_shared(
    cert: &Certificate,
    tree: &HashTree<Vec<u8>>,
    agent: &Agent,
    canister_id: Principal,
) -> Result<(), Error> {
    // Verify via agent
    agent
        .verify(cert, canister_id)
        .context("agent failed to verify certificate")?;

    // Lookup witness value
    let witness = lookup_value(
        cert,
        vec![
            "canister".as_bytes(),
            canister_id.as_slice(),
            "certified_data".as_bytes(),
        ],
    )
    .context("failed to lookup witness")?;

    // Verify witness against tree
    if tree.digest() != witness {
        return Err(anyhow!("tree digest does not match witness"));
    }

    Ok(())
}

// Given the ic_certified_map hash tree, chceck that it certifies key->hash(val)
fn validate_package(tree: &HashTree<Vec<u8>>, key: &str, val: &[u8]) -> Result<(), Error> {
    let tree_sha = match tree.lookup_path(&[LABEL_DOMAINS, key.as_bytes()]) {
        LookupResult::Found(v) => Ok(v),
        _ => Err(anyhow!("failed to lookup path in tree")),
    }?;

    if tree_sha != Sha256::digest(val).as_slice() {
        return Err(anyhow!("value sha does not match tree sha"));
    }

    Ok(())
}

// Vector indicating the sequence of pruned nodes and leaves in the provided hash tree
fn indicator_vector(node: &HashTreeNode<Vec<u8>>) -> Vec<bool> {
    match node {
        // Simple
        HashTreeNode::Empty() => vec![],
        HashTreeNode::Leaf(_) => vec![true],
        HashTreeNode::Pruned(_) => vec![false],

        // Recurse
        HashTreeNode::Labeled(_, a) => indicator_vector(a),
        HashTreeNode::Fork(a) => [&a.0, &a.1].map(indicator_vector).concat(),
    }
}
