use candid::{CandidType, IDLValue};

/// Pretty print `value` into a Candid string.
///
/// Example:
///
/// ```rust
/// #[derive(CandidType)]
/// struct DummyCandidStruct {
///     pub status: Option<i32>,
///     pub module_hash: Vec<u8>,
///     pub controllers: String,
///     pub memory_size: Option<u64>,
///     pub cycles: Option<u64>,
/// }
///
/// let dummy = DummyCandidStruct {
///     status: Some(42),
///     module_hash: vec![1, 2, 3, 4],
///     controllers: "foo".to_string(),
///     memory_size: Some(100),
///     cycles: Some(123),
/// };
/// println!("{}", pretty(&dummy));
/// ```
///
/// Output:
/// ```candid
/// record {
///   status = opt (42 : int32);
///   controllers = "foo";
///   memory_size = opt (100 : nat64);
///   cycles = opt (123 : nat64);
///   module_hash = blob "\01\02\03\04";
/// }
/// ```
pub fn pretty<T: CandidType>(value: &T) -> Result<String, String> {
    let value = IDLValue::try_from_candid_type(value).map_err(|err| err.to_string())?;

    Ok(value.to_string())
}

#[cfg(test)]
mod tests;
