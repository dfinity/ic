use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Dep {
    Version(VersionReq),
    VersionExtra(NormalDep),
    Local(LocalDep),
    Git(GitDep),
}

impl Dep {
    pub fn as_version_req(&self) -> Option<&VersionReq> {
        match self {
            Self::Version(v) => Some(v),
            Self::VersionExtra(NormalDep { version, .. }) => Some(version),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct NormalDep {
    pub version: VersionReq,
    #[serde(default)]
    pub package: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct LocalDep {
    pub path: String,
}

#[derive(Deserialize, Debug)]
pub struct GitDep {
    #[serde(rename = "git")]
    pub _git: String,
}
