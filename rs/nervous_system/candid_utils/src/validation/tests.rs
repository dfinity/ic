use super::*;

#[test]
fn test_candid_service_arg_validation() {
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
            "Invalid service",
            r#"
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "()",
            Err(()),
        ),
        (
            "Invalid arg",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "",
            Err(()),
        ),
        (
            "Complex service with two arguments (happy)",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "(record {}, (11 : nat32))",
            Ok(()),
        ),
        (
            "Complex service with two arguments (missing 1st arg)",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "((11 : nat32))",
            Err(()),
        ),
        (
            "Complex service with two arguments (missing 2nd arg)",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "(record {})",
            Err(()),
        ),
        (
            "Complex service with two arguments (missing both args)",
            r#"
                type List = opt record { head: int; tail: List };
                type byte = nat8;
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    f : (byte, int, nat, int8) -> (List);
                    g : (List) -> (int) query;
                }
            "#,
            "()",
            Err(()),
        ),
        (
            "Trivial service with two arguments (wrong arg order)",
            r#"
                service : (x : record { foo : opt record {} }, y : nat32) -> {
                    g : () -> (int) query;
                }
            "#,
            "((11 : nat32), record {})",
            Err(()),
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
            "Trivial service with one record argument (extra field breaks subtyping)",
            r#"
                service : (x : record { foo : opt nat; bar : nat }) -> {
                    g : () -> (int) query;
                }
            "#,
            "(record { foobar = (1984 : nat); foo = opt (42 : nat) })",
            Err(()),
        ),
    ] {
        let observed_result =
            validate_upgrade_args(candid_service.to_string(), upgrade_arg.to_string());

        match (observed_result, expected_result) {
            (Ok(_), Ok(())) => (),
            (Err(_), Err(())) => (),
            (Err(err), Ok(())) => {
                println!("{}", err);
                panic!("Test `{label}` FAILED, although it is expected to succeed.");
            }
            (Ok(_), Err(())) => {
                panic!("Test `{label}` SUCCEEDED, although it is expected to fail.");
            }
        }
    }
}
