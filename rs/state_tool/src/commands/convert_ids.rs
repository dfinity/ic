use std::str::FromStr;

use ic_types::{CanisterId, PrincipalId};

pub fn do_canister_id_to_hex(canister_id: String) -> Result<(), String> {
    let canister = CanisterId::from_str(&canister_id).map_err(|e| e.to_string())?;
    println!(
        "hex(canister_id): {}",
        hex::encode(canister.get_ref().as_slice())
    );
    Ok(())
}

pub fn do_canister_id_from_hex(canister_id: String) -> Result<(), String> {
    let canister = hex::decode(canister_id).map_err(|e| e.to_string())?;
    println!(
        "canister_id: {}",
        CanisterId::new(PrincipalId::try_from(&canister[..]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    );
    Ok(())
}

pub fn do_principal_from_byte_string(bytes: String) -> Result<(), String> {
    let bytes: Vec<u8> = bytes
        .trim()
        .replace('[', "")
        .replace(']', "")
        .split(',')
        .map(|byte| byte.trim().parse().unwrap())
        .collect();
    println!(
        "{}",
        PrincipalId::try_from(bytes.as_slice()).map_err(|e| e.to_string())?
    );

    Ok(())
}
