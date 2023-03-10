use std::time::Instant;

use ic_agent::{Agent, Identity};

use crate::{
    canister_api::{Request, Response},
    driver::test_env_api::{HasPublicApiUrl, IcNodeSnapshot},
    generic_workload_engine::metrics::RequestOutcome,
    util::{assert_create_agent, assert_create_agent_with_identity, block_on, delay},
};

/// An agent that is well-suited for interacting with arbitrary IC canisters.
#[derive(Clone)]
pub struct CanisterAgent {
    pub agent: Agent,
}

pub trait HasSnsAgentCapability: HasPublicApiUrl + Send + Sync {
    fn build_canister_agent(&self) -> CanisterAgent;
    fn build_canister_agent_with_identity(
        &self,
        identity: impl Identity + Clone + 'static,
    ) -> CanisterAgent;
}

impl HasSnsAgentCapability for IcNodeSnapshot {
    fn build_canister_agent(&self) -> CanisterAgent {
        let agent = block_on(assert_create_agent(self.get_public_url().as_str()));
        CanisterAgent { agent }
    }

    fn build_canister_agent_with_identity(
        &self,
        identity: impl Identity + Clone + 'static,
    ) -> CanisterAgent {
        let agent = block_on(assert_create_agent_with_identity(
            self.get_public_url().as_str(),
            identity,
        ));
        CanisterAgent { agent }
    }
}

impl CanisterAgent {
    pub fn from_boundary_node_url(bn_url: &str) -> Self {
        Self {
            agent: block_on(assert_create_agent(bn_url)),
        }
    }

    pub fn get(&self) -> Agent {
        self.agent.clone()
    }

    pub async fn call<T>(
        &self,
        request: &(dyn Request<T> + Send + Sync),
    ) -> RequestOutcome<Vec<u8>, String>
    where
        T: Response,
    {
        let start_time = Instant::now();
        let result = (if request.is_query() {
            self.agent
                .query(&request.canister_id(), request.method_name())
                .with_arg(request.payload())
                .call()
                .await
        } else {
            self.agent
                .update(&request.canister_id(), request.method_name())
                .with_arg(request.payload())
                .call_and_wait(delay())
                .await
        })
        .map_err(|e| format!("{e:?}"));
        RequestOutcome::new(
            result,
            // TODO: incorporate canister IDs into labels to avoid collisions if two canisters have endpoints with the same name
            request.method_name(),
            start_time.elapsed(),
            1,
        )
    }

    pub async fn call_and_parse<T>(
        &self,
        request: &(dyn Request<T> + Send + Sync),
    ) -> RequestOutcome<T, String>
    where
        T: Response + Clone,
    {
        let raw_outcome = self.call(request).await;
        RequestOutcome::new(
            raw_outcome.result().map(|r| {
                request
                    .parse_response(r.as_slice())
                    .expect("failed to decode")
            }),
            format!("{}+parse", request.method_name()),
            raw_outcome.duration,
            raw_outcome.attempts,
        )
    }
}
