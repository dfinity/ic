//! Module that deals with requests to /api/v2/canister/.../read_state

use crate::HttpError;
use hyper::StatusCode;
use ic_types::PrincipalId;

pub(crate) mod canister;
pub(crate) mod subnet;

fn parse_principal_id(principal_id: &[u8]) -> Result<PrincipalId, HttpError> {
    match PrincipalId::try_from(principal_id) {
        Ok(principal_id) => Ok(principal_id),
        Err(err) => Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse principal ID: {}.", err),
        }),
    }
}

fn verify_principal_ids(
    principal_id: &PrincipalId,
    effective_principal_id: &PrincipalId,
) -> Result<(), HttpError> {
    if principal_id != effective_principal_id {
        return Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "Effective principal id in URL {} does not match requested principal id: {}.",
                effective_principal_id, principal_id
            ),
        });
    }
    Ok(())
}
