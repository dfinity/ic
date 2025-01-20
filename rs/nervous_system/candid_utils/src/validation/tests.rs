use super::*;

#[test]
fn test_candid_service_arg_validation() {
    let complex_service = r#"
        type List = opt record { head: int; tail: List };
        type byte = nat8;
        service : (x : record { foo : opt record {} }, y : nat32) -> {
            f : (byte, int, nat, int8) -> (List);
            g : (List) -> (int) query;
        }
    "#;
    let dummy_error_text = "dummy_error_text".to_string();

    for (label, candid_service, upgrade_arg, expected_result) in [
        (
            "Service without args",
            r#"
                service : {
                    g : () -> (int) query;
                }
            "#,
            "()",
            Ok(()),
        ),
        (
            "Invalid service (unbound type List)",
            r#"
                service : () -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "()",
            Err(CandidServiceArgValidationError::BadService(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Arg is an empty string",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    g : () -> (int) query;
                }
            "#,
            "",
            Err(CandidServiceArgValidationError::ArgsParseError(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Complex service with two arguments (happy)",
            complex_service,
            "(record {}, (11 : nat32))",
            Ok(()),
        ),
        (
            "Complex service with two arguments (missing 1st arg)",
            complex_service,
            "((11 : nat32))",
            Err(CandidServiceArgValidationError::WrongArgumentCount(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Complex service with two arguments (missing 2nd arg)",
            complex_service,
            "(record {})",
            Err(CandidServiceArgValidationError::WrongArgumentCount(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Complex service with two arguments (missing both args)",
            complex_service,
            "()",
            Err(CandidServiceArgValidationError::WrongArgumentCount(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Trivial service with two arguments (wrong arg order)",
            r#"
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    g : () -> (int) query;
                }
            "#,
            "((11 : nat32), record {})",
            Err(CandidServiceArgValidationError::SubtypingErrors(
                dummy_error_text.clone(),
            )),
        ),
        (
            "Trivial service with one record argument (subtyping holds)",
            r#"
                service : (x : record { foo : opt nat; bar : opt nat }) -> {
                    g : () -> (int) query;
                }
            "#,
            "(record { foobar = opt (1984 : nat); foo = opt (42 : nat) })",
            Ok(()),
        ),
        (
            "Trivial service with one record argument (missing required field)",
            r#"
                service : (record { foo : nat; }) -> {
                    g : () -> (int) query;
                }
            "#,
            "(record { bar = (1984 : nat) })",
            Err(CandidServiceArgValidationError::SubtypingErrors(
                dummy_error_text,
            )),
        ),
    ] {
        let observed_result =
            validate_upgrade_args(candid_service.to_string(), upgrade_arg.to_string());

        match (observed_result, expected_result) {
            (Ok(_), Ok(())) => (),
            (Err(observed_err), Err(expected_err)) => {
                if observed_err != expected_err {
                    panic!(
                        "Test `{label}` failed unexpectedly. Expected {}, observed {}:\n{}",
                        expected_err.kind(),
                        observed_err.kind(),
                        observed_err.message(),
                    );
                }
            }
            (Err(observed_err), Ok(())) => {
                println!("{}", observed_err.message());
                panic!(
                    "Test `{label}` FAILED with {}, although it is expected to succeed.",
                    observed_err.kind()
                );
            }
            (Ok(_), Err(expected_err)) => {
                panic!(
                    "Test `{label}` SUCCEEDED, although it is expected to fail with {}.",
                    expected_err.kind()
                );
            }
        }
    }
}
