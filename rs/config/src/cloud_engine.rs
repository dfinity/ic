use ic_base_types::{CanisterId, PrincipalId};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

/// Engine management canister on mainnet. Other environments have to configure
/// their own via the `cloud_engine` section of `ic.json5`.
pub const MAINNET_ENGINE_MANAGEMENT_CANISTER_ID: &str = "q6cfj-fyaaa-aaaar-qb77q-cai";

/// Configuration that only cloud engine nodes use.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Principal of the engine management canister, which an all-in-one node
    /// needs to discover the operator canister of its own engine. When unset,
    /// the node cannot find its operator and therefore does not run `ic-gateway`.
    #[serde(default, deserialize_with = "deserialize_canister_id")]
    pub engine_management_canister_id: Option<CanisterId>,
}

/// `CanisterId`'s own `Deserialize` casts rather than converts, so it accepts
/// any principal. Going through `PrincipalId` rejects one that could not be a
/// canister id while the configuration is read, instead of letting every lookup
/// fail against a principal that cannot exist.
fn deserialize_canister_id<'de, D>(deserializer: D) -> Result<Option<CanisterId>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(principal) = Option::<PrincipalId>::deserialize(deserializer)? else {
        return Ok(None);
    };

    CanisterId::try_from_principal_id(principal)
        .map(Some)
        .map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canister_id_is_accepted() {
        let config: Config = json5::from_str(&format!(
            r#"{{ engine_management_canister_id: "{MAINNET_ENGINE_MANAGEMENT_CANISTER_ID}" }}"#
        ))
        .expect("a canister id should be accepted");

        assert_eq!(
            config
                .engine_management_canister_id
                .expect("the id should be set")
                .to_string(),
            MAINNET_ENGINE_MANAGEMENT_CANISTER_ID
        );
    }

    #[test]
    fn a_principal_that_is_no_canister_id_is_rejected() {
        // The anonymous principal: a well-formed principal, but never a
        // canister id. `CanisterId`'s own `Deserialize` would let it through.
        let err = json5::from_str::<Config>(r#"{ engine_management_canister_id: "2vxsx-fae" }"#)
            .expect_err("a non-canister principal should be rejected");

        assert!(err.to_string().contains("not a valid canister ID"), "{err}");
    }

    #[test]
    fn the_id_is_optional() {
        let config: Config = json5::from_str("{}").expect("the section may be empty");

        assert_eq!(config.engine_management_canister_id, None);
    }

    #[test]
    fn an_explicit_null_is_none() {
        // What `ic.json5` carries on a node that has no engine management
        // canister configured.
        let config: Config = json5::from_str(r#"{ engine_management_canister_id: null }"#)
            .expect("an explicit null should be accepted");

        assert_eq!(config.engine_management_canister_id, None);
    }
}
