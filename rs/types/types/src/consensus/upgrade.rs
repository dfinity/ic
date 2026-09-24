//! Phase-2 quick-upgrade permit types.
//!
//! The permit flow works in three stages:
//!
//! 1. **Request**: A block maker includes `UpgradePermitAction::RequestPermit` in
//!    its block when it wants to reboot. Validators check outstanding requests
//!    against the allowed max parallel reboots.
//!
//! 2. **Authorize**: After the request block is executed, nodes gossip an
//!    [`UpgradeAuthorizationShare`]. When a block maker collects enough
//!    shares, it includes `UpgradePermitAction::AuthorizePermit` in its block.
//!
//! 3. **Return**: After rebooting, the node includes
//!    `UpgradePermitAction::ReturnPermit` to release the slot.

use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use serde::Serialize;

use crate::artifact::{IdentifiableArtifact, PbArtifact};
use crate::consensus::HasHeight;
use crate::crypto::{
    CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator, crypto_hash,
};
use crate::signature::{BasicSignatureBatch, BasicSigned};
use crate::{Height, NodeId, node_id_into_protobuf, node_id_try_from_option};

/// A single action in a block's upgrade payload section. A block may carry
/// multiple actions (e.g. `Request` for the block maker and `Authorize` for
/// another node).
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum UpgradePermitAction {
    /// Request permission to reboot. The block maker requests for itself.
    /// `request_height` is the height of the block containing this request,
    /// used for timeout tracking.
    RequestPermit(UpgradePermitRequest),
    /// Authorize a node to reboot — the signed request and the basic
    /// signatures over it collected from other nodes.
    AuthorizePermit(Signed<UpgradePermitRequest, BasicSignatureBatch<UpgradePermitRequest>>),
    /// Release a previously authorized permit (reboot complete).
    ReturnPermit { node: NodeId },
}

/// UpgradePermitRequest holds the values that are signed in an
/// upgrade permit authorization share.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct UpgradePermitRequest {
    pub requestor: NodeId,
    pub request_height: Height,
}

impl SignedBytesWithoutDomainSeparator for UpgradePermitRequest {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        serde_cbor::to_writer(bytes, &self).unwrap();
    }
}

impl HasHeight for UpgradePermitRequest {
    fn height(&self) -> Height {
        self.request_height
    }
}

pub type UpgradeAuthorizationShare = BasicSigned<UpgradePermitRequest>;

/// Upgrade permit authorization message identifier carries both a message hash
/// and a height, used by the upgrade permit auth pool for lookup.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UpgradeAuthorizationShareId {
    pub height: Height,
    pub hash: CryptoHashOf<UpgradeAuthorizationShare>,
}

impl HasHeight for UpgradeAuthorizationShareId {
    fn height(&self) -> Height {
        self.height
    }
}

impl IdentifiableArtifact for UpgradeAuthorizationShare {
    const NAME: &'static str = "upgrade";
    type Id = UpgradeAuthorizationShareId;
    fn id(&self) -> Self::Id {
        UpgradeAuthorizationShareId {
            hash: crypto_hash(self),
            height: self.content.height(),
        }
    }
}

impl From<&UpgradeAuthorizationShare> for UpgradeAuthorizationShareId {
    fn from(share: &UpgradeAuthorizationShare) -> Self {
        share.id()
    }
}

impl PbArtifact for UpgradeAuthorizationShare {
    type PbId = pb::UpgradeAuthorizationShareId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = pb::UpgradeAuthorizationShare;
    type PbMessageError = ProxyDecodeError;
}

impl From<&UpgradePermitRequest> for pb::UpgradePermitRequest {
    fn from(content: &UpgradePermitRequest) -> Self {
        pb::UpgradePermitRequest {
            requestor: Some(node_id_into_protobuf(content.requestor)),
            request_height: content.request_height.get(),
        }
    }
}

impl TryFrom<pb::UpgradePermitRequest> for UpgradePermitRequest {
    type Error = ProxyDecodeError;

    fn try_from(content: pb::UpgradePermitRequest) -> Result<Self, Self::Error> {
        Ok(UpgradePermitRequest {
            requestor: node_id_try_from_option(content.requestor)?,
            request_height: Height::from(content.request_height),
        })
    }
}

impl From<UpgradeAuthorizationShare> for pb::UpgradeAuthorizationShare {
    fn from(share: UpgradeAuthorizationShare) -> Self {
        pb::UpgradeAuthorizationShare {
            request: Some(pb::UpgradePermitRequest::from(&share.content)),
            signature: Some(pb::BasicSignature::from(share.signature)),
        }
    }
}

impl TryFrom<pb::UpgradeAuthorizationShare> for UpgradeAuthorizationShare {
    type Error = ProxyDecodeError;

    fn try_from(message: pb::UpgradeAuthorizationShare) -> Result<Self, Self::Error> {
        let content = try_from_option_field(message.request, "UpgradeAuthorizationShare::request")?;
        let signature =
            try_from_option_field(message.signature, "UpgradeAuthorizationShare::signature")?;
        Ok(UpgradeAuthorizationShare { content, signature })
    }
}

impl From<UpgradeAuthorizationShareId> for pb::UpgradeAuthorizationShareId {
    fn from(id: UpgradeAuthorizationShareId) -> Self {
        Self {
            hash: id.hash.get().0,
            height: id.height.get(),
        }
    }
}

impl TryFrom<pb::UpgradeAuthorizationShareId> for UpgradeAuthorizationShareId {
    type Error = ProxyDecodeError;

    fn try_from(id: pb::UpgradeAuthorizationShareId) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: CryptoHash(id.hash).into(),
            height: Height::from(id.height),
        })
    }
}
