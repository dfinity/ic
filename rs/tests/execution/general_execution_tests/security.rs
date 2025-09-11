/* tag::catalog[]
Title:: Security tests

Goal:: Canister execution cannot crash the replica.

Runbook::
. Deploy one subnet.
. Deploy a canister whose execution results in stack overflow.
. Assert that the execution results in a reject message with the corresponding reason instead of crashing the replica.

end::catalog[] */
use ic_agent::AgentError;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
    },
    util::*,
};

pub fn stack_overflow(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Deploy a canister whose execution results in stack overflow.
            let wasm_module = wat::parse_str(
                r#"
                (module
                    (func $f (export "canister_update foo")
                        ;; Define many local variables to quickly overflow the stack
                        (local i64) (local i64) (local i64) (local i64) (local i64)
                        (local i64) (local i64) (local i64) (local i64) (local i64)
                        (local i64) (local i64) (local i64) (local i64) (local i64)
                        (local i64) (local i64) (local i64) (local i64) (local i64)
                        ;; call "f" recursively
                        (call $f)
                    )
                    (memory 0)
                )"#,
            )
            .unwrap();

            let canister_id =
                create_and_install(&agent, node.effective_canister_id(), &wasm_module).await;

            // Call the method `foo` whose execution results in stack overflow.
            let err = agent
                .update(&canister_id, "foo")
                .call_and_wait()
                .await
                .expect_err("should fail");
            match err {
                AgentError::CertifiedReject { reject, .. } => {
                    assert!(
                        reject
                            .reject_message
                            .contains("Canister trapped: stack overflow")
                    );
                }
                _ => panic!("Unexpected error: {err:?}"),
            };
        }
    })
}
