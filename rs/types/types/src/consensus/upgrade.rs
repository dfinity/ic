//! Phase-2 quick-upgrade permit types.
//!
//! The permit flow works in three stages:
//!
//! 1. **Request**: A block maker includes `UpgradePermitAction::RequestPermit` in
//!    its block when it wants to reboot. Validators check outstanding requests
//!    against the allowed max parallel reboots.
//!
//! 2. **Authorize**: After the request block is executed, nodes gossip an
//!    [`UpgradePermitAuthorizationShare`]. When a block maker collects enough
//!    shares, it includes `UpgradePermitAction::AuthorizePermit` in its block.
//!
//! 3. **Return**: After rebooting, the node includes
//!    `UpgradePermitAction::ReturnPermit` to release the slot.

use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};

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
    RequestPermit(UpgradePermitAuthorizationRequest),
    /// Authorize a node to reboot — the signed request and the basic
    /// signatures over it collected from the staying members.
    AuthorizePermit(
        Signed<
            UpgradePermitAuthorizationRequest,
            BasicSignatureBatch<UpgradePermitAuthorizationRequest>,
        >,
    ),
    /// Release a previously authorized permit (reboot complete).
    ReturnPermit { node: NodeId },
}

/// UpgradePermitAuthorizationRequest holds the values that are signed in an
/// upgrade permit authorization share.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct UpgradePermitAuthorizationRequest {
    pub requestor: NodeId,
    pub request_height: Height,
}

impl SignedBytesWithoutDomainSeparator for UpgradePermitAuthorizationRequest {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        serde_cbor::to_writer(bytes, &self).unwrap();
    }
}

impl HasHeight for UpgradePermitAuthorizationRequest {
    fn height(&self) -> Height {
        self.request_height
    }
}

pub type UpgradePermitAuthorizationShare = BasicSigned<UpgradePermitAuthorizationRequest>;

/// Upgrade permit authorization message identifier carries both a message hash
/// and a height, used by the upgrade permit auth pool for lookup.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct UpgradePermitAuthorizationShareId {
    pub hash: CryptoHashOf<UpgradePermitAuthorizationShare>,
    pub height: Height,
}

impl HasHeight for UpgradePermitAuthorizationShareId {
    fn height(&self) -> Height {
        self.height
    }
}

impl IdentifiableArtifact for UpgradePermitAuthorizationShare {
    const NAME: &'static str = "upgrade";
    type Id = UpgradePermitAuthorizationShareId;
    fn id(&self) -> Self::Id {
        UpgradePermitAuthorizationShareId {
            hash: crypto_hash(self),
            height: self.content.height(),
        }
    }
}

impl From<&UpgradePermitAuthorizationShare> for UpgradePermitAuthorizationShareId {
    fn from(share: &UpgradePermitAuthorizationShare) -> Self {
        share.id()
    }
}

impl PbArtifact for UpgradePermitAuthorizationShare {
    type PbId = pb::UpgradePermitAuthorizationShareId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = pb::UpgradePermitAuthorizationShare;
    type PbMessageError = ProxyDecodeError;
}

impl From<&UpgradePermitAuthorizationRequest> for pb::UpgradePermitAuthorizationRequest {
    fn from(content: &UpgradePermitAuthorizationRequest) -> Self {
        pb::UpgradePermitAuthorizationRequest {
            requestor: Some(node_id_into_protobuf(content.requestor)),
            request_height: content.request_height.get(),
        }
    }
}

impl TryFrom<pb::UpgradePermitAuthorizationRequest> for UpgradePermitAuthorizationRequest {
    type Error = ProxyDecodeError;

    fn try_from(content: pb::UpgradePermitAuthorizationRequest) -> Result<Self, Self::Error> {
        Ok(UpgradePermitAuthorizationRequest {
            requestor: node_id_try_from_option(content.requestor)?,
            request_height: Height::from(content.request_height),
        })
    }
}

impl From<UpgradePermitAuthorizationShare> for pb::UpgradePermitAuthorizationShare {
    fn from(share: UpgradePermitAuthorizationShare) -> Self {
        pb::UpgradePermitAuthorizationShare {
            request: Some(pb::UpgradePermitAuthorizationRequest::from(&share.content)),
            signature: Some(pb::BasicSignature::from(share.signature)),
        }
    }
}

impl TryFrom<pb::UpgradePermitAuthorizationShare> for UpgradePermitAuthorizationShare {
    type Error = ProxyDecodeError;

    fn try_from(message: pb::UpgradePermitAuthorizationShare) -> Result<Self, Self::Error> {
        let content =
            try_from_option_field(message.request, "UpgradePermitAuthorizationShare::request")?;
        let signature = try_from_option_field(
            message.signature,
            "UpgradePermitAuthorizationShare::signature",
        )?;
        Ok(UpgradePermitAuthorizationShare { content, signature })
    }
}

impl From<UpgradePermitAuthorizationShareId> for pb::UpgradePermitAuthorizationShareId {
    fn from(id: UpgradePermitAuthorizationShareId) -> Self {
        Self {
            hash: id.hash.get().0,
            height: id.height.get(),
        }
    }
}

impl TryFrom<pb::UpgradePermitAuthorizationShareId> for UpgradePermitAuthorizationShareId {
    type Error = ProxyDecodeError;

    fn try_from(id: pb::UpgradePermitAuthorizationShareId) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: CryptoHash(id.hash).into(),
            height: Height::from(id.height),
        })
    }
}
