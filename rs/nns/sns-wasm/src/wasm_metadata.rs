use crate::pb::v1::{
    GetWasmMetadataRequest as GetWasmMetadataRequestPb,
    GetWasmMetadataResponse as GetWasmMetadataResponsePb, MetadataSection as MetadataSectionPb,
    SnsWasmError as SnsWasmErrorPb, get_wasm_metadata_response,
};

pub const MAX_METADATA_SECTION_NAME_BYTES: usize = 100;
pub const MAX_METADATA_SECTION_CONTENTS_BYTES: usize = 100_000;

impl TryFrom<GetWasmMetadataRequestPb> for [u8; 32] {
    type Error = String;

    /// First, etract the hash from the request payload. Second, convert it to a u8-array of
    /// length 32 (the size of our sha256 hash). Return an error if the input's length is incorrect.
    fn try_from(src: GetWasmMetadataRequestPb) -> Result<Self, Self::Error> {
        let Some(hash) = src.hash else {
            return Err("GetWasmMetadataRequest.bytes must be specified.".to_string());
        };

        let Ok(hash) = Self::try_from(hash) else {
            return Err("GetWasmMetadataRequest.bytes must contain exactly 32 bytes.".to_string());
        };

        Ok(hash)
    }
}

/// The internal representation of `MetadataSectionPb`.
#[derive(Debug)]
pub struct MetadataSection {
    pub visibility: String,
    pub name: String,
    pub contents: Vec<u8>,
}

impl MetadataSection {
    pub fn validate(&self) -> Result<(), String> {
        let mut errs = vec![];
        if !["icp:private", "icp:public"]
            .iter()
            .any(|allowed_visibility| allowed_visibility == &self.visibility)
        {
            errs.push(".visibility should be `icp:private` or `icp:public`.".to_string());
        }
        if self.name.is_empty() {
            errs.push(".name must not be the empty string.".to_string());
        }
        if self.name.len() > MAX_METADATA_SECTION_NAME_BYTES {
            errs.push(format!(
                ".name must fit into at most {MAX_METADATA_SECTION_NAME_BYTES} bytes."
            ));
        }
        if self.contents.len() > MAX_METADATA_SECTION_CONTENTS_BYTES {
            errs.push(format!(
                ".contents must fit into at most {MAX_METADATA_SECTION_CONTENTS_BYTES} bytes."
            ));
        }
        if !errs.is_empty() {
            let errs = errs.join(", ");
            return Err(format!("Invalid MetadataSection: {errs}"));
        }

        Ok(())
    }
}

impl From<MetadataSection> for MetadataSectionPb {
    fn from(src: MetadataSection) -> Self {
        Self {
            visibility: Some(src.visibility),
            name: Some(src.name),
            contents: Some(src.contents),
        }
    }
}

impl TryFrom<MetadataSectionPb> for MetadataSection {
    type Error = String;

    fn try_from(src: MetadataSectionPb) -> Result<Self, Self::Error> {
        let MetadataSectionPb {
            visibility,
            name,
            contents,
        } = src;

        let Some(visibility) = visibility else {
            return Err("Required field MetadataSection.visibility is not specified.".to_string());
        };
        let Some(name) = name else {
            return Err("Required field MetadataSection.name is not specified".to_string());
        };
        let Some(contents) = contents else {
            return Err("Required field MetadataSection.contents is not specified".to_string());
        };

        Ok(Self {
            visibility,
            name,
            contents,
        })
    }
}

impl From<Result<Vec<MetadataSection>, String>> for GetWasmMetadataResponsePb {
    fn from(src: Result<Vec<MetadataSection>, String>) -> Self {
        use get_wasm_metadata_response::{Ok, Result};
        let result = match src {
            Err(message) => Result::Error(SnsWasmErrorPb { message }),
            Ok(sections) => Result::Ok(Ok {
                sections: sections.into_iter().map(MetadataSectionPb::from).collect(),
            }),
        };
        Self {
            result: Some(result),
        }
    }
}
