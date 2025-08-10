use super::*;
use ic_protobuf::{proxy::ProxyDecodeError, state::canister_state_bits::v1 as pb};

impl From<&ExportedFunctions> for Vec<pb::WasmMethod> {
    fn from(item: &ExportedFunctions) -> Self {
        item.exported_functions.iter().map(From::from).collect()
    }
}

impl TryFrom<Vec<pb::WasmMethod>> for ExportedFunctions {
    type Error = ProxyDecodeError;
    fn try_from(value: Vec<pb::WasmMethod>) -> Result<Self, Self::Error> {
        Ok(ExportedFunctions::new(
            value
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl From<pb::NextScheduledMethod> for NextScheduledMethod {
    fn from(val: pb::NextScheduledMethod) -> Self {
        match val {
            pb::NextScheduledMethod::Unspecified | pb::NextScheduledMethod::GlobalTimer => {
                NextScheduledMethod::GlobalTimer
            }
            pb::NextScheduledMethod::Heartbeat => NextScheduledMethod::Heartbeat,
            pb::NextScheduledMethod::Message => NextScheduledMethod::Message,
        }
    }
}

impl From<NextScheduledMethod> for pb::NextScheduledMethod {
    fn from(val: NextScheduledMethod) -> Self {
        match val {
            NextScheduledMethod::GlobalTimer => pb::NextScheduledMethod::GlobalTimer,
            NextScheduledMethod::Heartbeat => pb::NextScheduledMethod::Heartbeat,
            NextScheduledMethod::Message => pb::NextScheduledMethod::Message,
        }
    }
}

impl From<&CustomSectionType> for pb::CustomSectionType {
    fn from(item: &CustomSectionType) -> Self {
        match item {
            CustomSectionType::Public => pb::CustomSectionType::Public,
            CustomSectionType::Private => pb::CustomSectionType::Private,
        }
    }
}

impl TryFrom<pb::CustomSectionType> for CustomSectionType {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::CustomSectionType) -> Result<Self, Self::Error> {
        match item {
            pb::CustomSectionType::Public => Ok(CustomSectionType::Public),
            pb::CustomSectionType::Private => Ok(CustomSectionType::Private),
            pb::CustomSectionType::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "CustomSectionType::Unspecified",
                err: "Encountered error while decoding CustomSection type".to_string(),
            }),
        }
    }
}

impl From<&CustomSection> for pb::WasmCustomSection {
    fn from(item: &CustomSection) -> Self {
        Self {
            visibility: pb::CustomSectionType::from(&item.visibility).into(),
            content: item.content.clone(),
            hash: Some(item.hash.to_vec()),
        }
    }
}

impl TryFrom<pb::WasmCustomSection> for CustomSection {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::WasmCustomSection) -> Result<Self, Self::Error> {
        let visibility = CustomSectionType::try_from(
            pb::CustomSectionType::try_from(item.visibility).unwrap_or_default(),
        )?;
        Ok(Self {
            visibility,
            hash: match item.hash {
                Some(hash_bytes) => hash_bytes.try_into().map_err(|h: Vec<u8>| {
                    ProxyDecodeError::InvalidDigestLength {
                        expected: 32,
                        actual: h.len(),
                    }
                })?,
                None => ic_hashtree_leaf_hash(&item.content),
            },
            content: item.content,
        })
    }
}

impl From<&WasmMetadata> for pb::WasmMetadata {
    fn from(item: &WasmMetadata) -> Self {
        let custom_sections = item
            .custom_sections
            .iter()
            .map(|(name, custom_section)| {
                (name.clone(), pb::WasmCustomSection::from(custom_section))
            })
            .collect();
        Self { custom_sections }
    }
}

impl TryFrom<pb::WasmMetadata> for WasmMetadata {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::WasmMetadata) -> Result<Self, Self::Error> {
        let custom_sections = item
            .custom_sections
            .into_iter()
            .map(
                |(name, custom_section)| match CustomSection::try_from(custom_section) {
                    Ok(custom_section) => Ok((name, custom_section)),
                    Err(err) => Err(err),
                },
            )
            .collect::<Result<_, _>>()?;
        Ok(WasmMetadata::new(custom_sections))
    }
}
