use candid::{CandidType, IDLValue};

pub fn pretty<T: CandidType>(value: T) -> Result<String, String> {
    let value_pretty: String = IDLValue::try_from_candid_type(&value)
        .map_err(|err| err.to_string())?
        .to_string();

    Ok(value_pretty.to_string())
}

#[cfg(test)]
mod tests;
