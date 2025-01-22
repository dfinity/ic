use candid::{CandidType, IDLValue};

pub fn pretty<T: CandidType>(value: T) -> Result<String, String> {
    let value = IDLValue::try_from_candid_type(&value).map_err(|err| err.to_string())?;

    Ok(value.to_string())
}

#[cfg(test)]
mod tests;
