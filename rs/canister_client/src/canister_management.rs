//! Functions for clients to talk to the Management Canister, a.k.a ic:00.
use crate::agent::Agent;

use ic_types::ic00::{InstallCodeArgs, Method, Payload, IC_00};

impl Agent {
    // Ships a binary wasm module to a canister.
    pub async fn install_canister(&self, install_args: InstallCodeArgs) -> Result<(), String> {
        self.execute_update(&IC_00, Method::InstallCode, install_args.encode(), vec![])
            .await
            .map(|_| ())
    }
}
