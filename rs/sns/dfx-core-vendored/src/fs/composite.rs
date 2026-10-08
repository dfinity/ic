use crate::error::fs::EnsureDirExistsError;
use crate::error::fs::EnsureDirExistsError::NotADirectory;
use std::path::Path;

pub fn ensure_dir_exists(p: &Path) -> Result<(), EnsureDirExistsError> {
    if !p.exists() {
        crate::fs::create_dir_all(p)?;
        Ok(())
    } else if !p.is_dir() {
        Err(NotADirectory(p.to_path_buf()))
    } else {
        Ok(())
    }
}
