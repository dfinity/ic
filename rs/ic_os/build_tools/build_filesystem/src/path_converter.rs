use std::path::{Path, PathBuf};

pub struct PathConverter {
    subdir: Option<PathBuf>,
}

impl PathConverter {
    pub fn new(subdir: Option<PathBuf>) -> Self {
        assert!(
            subdir.as_ref().is_none_or(|p| p.is_absolute()),
            "subdir must be absolute: {subdir:?}"
        );
        Self { subdir }
    }

    pub fn source_to_target(&self, source_path: &ImagePath) -> Option<ImagePath> {
        match &self.subdir {
            Some(subdir) => match source_path.0.strip_prefix(subdir) {
                Ok(stripped) => Some(ImagePath::from(stripped.to_path_buf())),
                Err(_) => None,
            },
            None => Some(source_path.clone()),
        }
    }

    pub fn target_to_source(&self, target_path: &ImagePath) -> ImagePath {
        if let Some(subdir) = &self.subdir {
            ImagePath::from(subdir.join(target_path.as_relative_path()))
        } else {
            target_path.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePath(PathBuf);

impl ImagePath {
    pub fn root() -> ImagePath {
        Self(PathBuf::from("/"))
    }

    pub fn is_root(&self) -> bool {
        self.0 == PathBuf::from("/")
    }

    /// Returns the path with a leading slash (e.g. for SELinux)
    pub fn as_absolute_path(&self) -> &Path {
        &self.0
    }

    /// Returns the path without a leading slash (e.g. for path in the tar file)
    pub fn as_relative_path(&self) -> &Path {
        let stripped = &self.0.strip_prefix("/").unwrap();
        if *stripped == Path::new("") {
            Path::new(".")
        } else {
            stripped
        }
    }
}

impl<T: Into<PathBuf>> From<T> for ImagePath {
    fn from(path: T) -> Self {
        let mut path = path.into();
        if !path.starts_with("/") {
            path = PathBuf::from("/").join(path);
        }

        if path.ends_with("/") && path != PathBuf::from("/") {
            path.pop();
        }

        Self(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_path_from_absolute() {
        let path = ImagePath::from("/opt/ic/bin");
        assert_eq!(path.as_absolute_path(), Path::new("/opt/ic/bin"));
        assert_eq!(path.as_relative_path(), Path::new("opt/ic/bin"));
    }

    #[test]
    fn test_image_path_from_relative() {
        let path = ImagePath::from("opt/ic/bin");
        assert_eq!(path.as_absolute_path(), Path::new("/opt/ic/bin"));
        assert_eq!(path.as_relative_path(), Path::new("opt/ic/bin"));
    }

    #[test]
    fn test_image_path_root_as_relative() {
        let path = ImagePath::root();
        assert_eq!(path.as_absolute_path(), Path::new("/"));
        assert_eq!(path.as_relative_path(), Path::new("."));
    }

    #[test]
    fn test_path_converter_no_subdir_source_to_target() {
        let converter = PathConverter::new(None);
        let source = ImagePath::from("/opt/ic/bin/replica");
        let target = converter.source_to_target(&source);
        assert_eq!(target, Some(ImagePath::from("/opt/ic/bin/replica")));
    }

    #[test]
    fn test_path_converter_with_subdir_source_to_target_match() {
        let converter = PathConverter::new(Some(PathBuf::from("/opt/ic")));
        let source = ImagePath::from("/opt/ic/bin/replica");
        let target = converter.source_to_target(&source);
        assert_eq!(target, Some(ImagePath::from("/bin/replica")));
    }

    #[test]
    fn test_path_converter_with_subdir_source_to_target_no_match() {
        let converter = PathConverter::new(Some(PathBuf::from("/opt/ic")));
        let source = ImagePath::from("/usr/bin/replica");
        let target = converter.source_to_target(&source);
        assert_eq!(target, None);
    }

    #[test]
    fn test_path_converter_target_to_source_no_subdir() {
        let converter = PathConverter::new(None);
        let target = ImagePath::from("/opt/ic/bin/replica");
        let source = converter.target_to_source(&target);
        assert_eq!(source.as_absolute_path(), Path::new("/opt/ic/bin/replica"));
    }

    #[test]
    fn test_path_converter_target_to_source_with_subdir() {
        let converter = PathConverter::new(Some(PathBuf::from("/opt/ic")));
        let target = ImagePath::from("/bin/replica");
        let source = converter.target_to_source(&target);
        assert_eq!(source.as_absolute_path(), Path::new("/opt/ic/bin/replica"));
    }

    #[test]
    fn test_path_converter_target_to_source_root_no_subdir() {
        let converter = PathConverter::new(None);
        let target = ImagePath::root();
        let source = converter.target_to_source(&target);
        assert_eq!(source.as_absolute_path(), Path::new("/"));
        assert_eq!(source.as_relative_path(), Path::new("."));
    }
}
