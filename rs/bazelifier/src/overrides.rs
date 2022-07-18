use std::{borrow::Cow, collections::HashMap};

use lazy_static::lazy_static;
use maplit::hashmap;
use semver::Version;

use crate::deps::*;

lazy_static! {
    static ref VERSION_OVERRIDES: HashMap<&'static str, Vec<Version>> = hashmap! {
        "mockall" => vec![Version::new(0, 7, 2)],
        "rand" => vec![
            Version::new(0, 4, 6),
            Version::new(0, 7, 3),
            Version::new(0, 8, 4),
        ],
        "rand_chacha" => vec![Version::new(0, 3, 1)],
    };
    static ref PKG_OVERRIDES: HashMap<&'static str, NameOverride<'static>> = hashmap! {
        "wabt" => NameOverride {
            name: "wabt".into(),
            repo: Some("wabt_rs"),
        },
        "lmdb-rkv" => NameOverride {
            name: "lmdb_rkv".into(),
            repo: Some("lmdb_rkv"),
        },
        "lmdb-rkv-sys" => NameOverride {
            name: "lmdb-sys:lmdb-sys".into(),
            repo: Some("lmdb_rkv"),
        }
    };
}

#[derive(Clone)]
pub struct NameOverride<'s> {
    pub name: Cow<'s, str>,
    pub repo: Option<&'s str>,
}

pub fn dep_name_override(name: &str, dep: &Dep) -> Option<NameOverride<'static>> {
    if let Some(o) = PKG_OVERRIDES.get(&name) {
        return Some(o.clone());
    }

    let req = dep.as_version_req()?;
    let overrides_list = VERSION_OVERRIDES.get(&name)?;

    for vers in overrides_list {
        if req.matches(vers) {
            return Some(NameOverride {
                name: format!("{}_{}_{}_{}", name, vers.major, vers.minor, vers.patch).into(),
                repo: None,
            });
        }
    }

    None
}
