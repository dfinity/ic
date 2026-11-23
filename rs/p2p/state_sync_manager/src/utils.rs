use ic_interfaces::p2p::state_sync::StateSyncArtifactId;
use ic_protobuf::{
    p2p::v1 as pb,
    proxy::{ProxyDecodeError, try_from_option_field},
};

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
            id: try_from_option_field(advert.id, "id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::{Height, crypto::CryptoHash};

    #[test]
    fn advert_roundtrip() {
        let advert = Advert {
            id: StateSyncArtifactId {
                height: Height::from(7),
                hash: CryptoHash::for_test(),
            },
        };

        assert_eq!(
            Advert::try_from(pb::Advert::from(advert.clone())).unwrap(),
            advert
        );
    }

    #[test]
    fn advert_without_id_is_rejected() {
        let result = Advert::try_from(pb::Advert { id: None });

        assert!(
            matches!(result, Err(ProxyDecodeError::MissingField("id"))),
            "{result:?}"
        );
    }

    #[test]
    fn advert_with_hash_of_wrong_length_is_rejected() {
        for len in [0, CryptoHash::LEN - 1, CryptoHash::LEN + 1] {
            let advert = pb::Advert {
                id: Some(pb::StateSyncId {
                    height: 7,
                    hash: vec![7; len],
                }),
            };

            let result = Advert::try_from(advert);

            assert!(
                matches!(
                    result,
                    Err(ProxyDecodeError::InvalidDigestLength { expected, actual })
                        if expected == CryptoHash::LEN && actual == len
                ),
                "{result:?}"
            );
        }
    }
}
