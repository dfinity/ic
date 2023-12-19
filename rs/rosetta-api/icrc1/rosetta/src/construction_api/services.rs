use super::types::MetadataOptions;
use rosetta_core::response_types::*;

pub fn construction_preprocess() -> ConstructionPreprocessResponse {
    ConstructionPreprocessResponse {
        options: Some(
            MetadataOptions {
                suggested_fee: true,
            }
            .into(),
        ),
        required_public_keys: None,
    }
}
