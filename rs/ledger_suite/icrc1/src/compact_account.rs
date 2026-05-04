use candid::Principal;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// A compact representation of an Account.
///
/// Instead of encoding accounts as structs with named fields,
/// we encode them as tuples with variables number of elements.
/// ```text
/// [bytes] <=> Account { owner: bytes, subaccount : None }
/// [x: bytes, y: bytes] <=> Account { owner: x, subaccount: Some(y) }
/// ```
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct CompactAccount(Vec<ByteBuf>);

impl From<Account> for CompactAccount {
    fn from(acc: Account) -> Self {
        let mut components = vec![ByteBuf::from(acc.owner.as_slice().to_vec())];
        if let Some(sub) = acc.subaccount {
            components.push(ByteBuf::from(sub.to_vec()))
        }
        CompactAccount(components)
    }
}

impl TryFrom<CompactAccount> for Account {
    type Error = String;
    fn try_from(compact: CompactAccount) -> Result<Account, String> {
        let elems = compact.0;
        if elems.is_empty() {
            return Err("account tuple must have at least one element".to_string());
        }
        if elems.len() > 2 {
            return Err(format!(
                "account tuple must have at most two elements, got {}",
                elems.len()
            ));
        }

        let principal =
            Principal::try_from(&elems[0][..]).map_err(|e| format!("invalid principal: {e}"))?;
        let subaccount = if elems.len() > 1 {
            Some(Subaccount::try_from(&elems[1][..]).map_err(|_| {
                format!(
                    "invalid subaccount: expected 32 bytes, got {}",
                    elems[1].len()
                )
            })?)
        } else {
            None
        };

        Ok(Account {
            owner: principal,
            subaccount,
        })
    }
}

pub(crate) mod opt {
    use super::*;

    pub(crate) fn serialize<S>(acc: &Option<Account>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        acc.map(CompactAccount::from).serialize(s)
    }

    pub(crate) fn deserialize<'de, D>(d: D) -> Result<Option<Account>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        type OptionalCompactAccount = Option<CompactAccount>;
        match OptionalCompactAccount::deserialize(d)? {
            Some(compact_account) => Account::try_from(compact_account)
                .map(Some)
                .map_err(D::Error::custom),
            None => Ok(None),
        }
    }
}
