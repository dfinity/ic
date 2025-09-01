use candid::{Decode, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc103::get_allowances::{
    Allowances, GetAllowancesArgs, GetAllowancesError,
};

pub fn list_allowances(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    args: GetAllowancesArgs,
) -> Result<Allowances, GetAllowancesError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc103_get_allowances",
            Encode!(&args)
            .unwrap()
        )
        .expect("failed to list allowances")
        .bytes(),
        Result<Allowances, GetAllowancesError>
    )
    .expect("failed to decode icrc103_get_allowances response")
}
