use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum CompareError {
    PathsDiffer {
        left: Vec<PathBuf>,
        right: Vec<PathBuf>,
    },
    ContentDiffers {
        path: PathBuf,
    },
    IoError {
        path: PathBuf,
        cause: std::io::Error,
    },
}

fn list_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    fn go(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    go(&path, files)?;
                } else {
                    files.push(path.to_path_buf());
                }
            }
        }
        Ok(())
    }
    let mut buf = vec![];
    go(dir, &mut buf)?;
    for path in buf.iter_mut() {
        *path = path
            .strip_prefix(dir)
            .expect("failed to strip path prefix")
            .to_path_buf();
    }
    buf.sort();
    Ok(buf)
}

pub fn compare(lhs: &Path, rhs: &Path) -> Result<(), CompareError> {
    let lhs_files = list_files(lhs).map_err(|e| CompareError::IoError {
        path: lhs.to_path_buf(),
        cause: e,
    })?;
    let rhs_files = list_files(rhs).map_err(|e| CompareError::IoError {
        path: rhs.to_path_buf(),
        cause: e,
    })?;
    if lhs_files != rhs_files {
        return Err(CompareError::PathsDiffer {
            left: lhs_files,
            right: rhs_files,
        });
    }
    for path in lhs_files.iter() {
        let lhs_path = lhs.join(path);
        let rhs_path = rhs.join(path);
        let lhs_file = std::fs::read(&lhs_path).map_err(|e| CompareError::IoError {
            path: lhs_path.to_path_buf(),
            cause: e,
        })?;
        let rhs_file = std::fs::read(&rhs_path).map_err(|e| CompareError::IoError {
            path: rhs_path.to_path_buf(),
            cause: e,
        })?;
        if lhs_file != rhs_file {
            return Err(CompareError::ContentDiffers {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}
