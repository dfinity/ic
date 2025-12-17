use ic_interfaces::p2p::state_sync::StateSyncArtifactId;
use ic_protobuf::{p2p::v1 as pb, proxy::ProxyDecodeError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Advert {
    pub(crate) id: StateSyncArtifactId,
}

impl From<Advert> for pb::Advert {
    fn from(advert: Advert) -> Self {
        pb::Advert {
            id: Some(advert.id.into()),
        }
    }
}

impl TryFrom<pb::Advert> for Advert {
    type Error = ProxyDecodeError;

    fn try_from(advert: pb::Advert) -> Result<Self, Self::Error> {
        Ok(Advert {
            id: advert
                .id
                .map(StateSyncArtifactId::from)
                .ok_or(ProxyDecodeError::MissingField("id"))?,
        })
    }
}
