use crate::error::structured_file::StructuredFileError;
use crate::error::structured_file::StructuredFileError::DeserializeJsonFileFailed;
use crate::error::structured_file::StructuredFileError::ReadJsonFileFailed;
use std::path::Path;

pub fn load_json_file<T: for<'a> serde::de::Deserialize<'a>>(
    path: &Path,
) -> Result<T, StructuredFileError> {
    let content = crate::fs::read(path).map_err(ReadJsonFileFailed)?;

    serde_json::from_slice(content.as_ref())
        .map_err(|err| DeserializeJsonFileFailed(Box::new(path.to_path_buf()), err))
}
