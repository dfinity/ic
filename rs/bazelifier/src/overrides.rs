use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use semver::Version;

use crate::deps::*;

type VersionOverride = (Version, &'static str);

lazy_static! {
    static ref VERSION_OVERRIDES: HashMap<&'static str, Vec<VersionOverride>> = hashmap! {
        "rand" => vec![
            (Version::new(0, 4, 6), "rand_0_4_6"),
            (Version::new(0, 7, 3), "rand_0_7_3"),
            (Version::new(0, 8, 4), "rand_0_8_4"),
        ],
        "rand_chacha" => vec![(Version::new(0, 3, 1), "rand_chacha_0_3_1")],
    };
    static ref PKG_OVERRIDES: HashMap<&'static str, NameOverride<'static>> = hashmap! {
        "wabt" => NameOverride {
            name: "wabt",
            repo: Some("wabt_rs"),
        },
        "lmdb-rkv" => NameOverride {
            name: "lmdb_rkv",
            repo: Some("lmdb_rkv"),
        },
        "lmdb-rkv-sys" => NameOverride {
            name: "lmdb-sys:lmdb-sys",
            repo: Some("lmdb_rkv"),
        }
    };
}

#[derive(Clone, Copy)]
pub struct NameOverride<'s> {
    pub name: &'s str,
    pub repo: Option<&'s str>,
}

pub fn dep_name_override(name: &str, dep: &Dep) -> Option<NameOverride<'static>> {
    if let Some(o) = PKG_OVERRIDES.get(&name) {
        return Some(*o);
    }

    let req = match dep {
        Dep::Version(v) => v,
        Dep::VersionExtra(NormalDep { version, .. }) => version,
        _ => return None,
    };
    let overrides_list = VERSION_OVERRIDES.get(&name)?;

    for (vers, override_) in overrides_list {
        if req.matches(vers) {
            return Some(NameOverride {
                name: *override_,
                repo: None,
            });
        }
    }

    None
}
