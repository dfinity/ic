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
