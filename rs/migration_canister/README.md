# Migration Canister

This canister orchestrates the migration of a canister ID from one subnet to another. 

## Technical overview

Canister migration involves several crossnet calls, which makes the process highly asynchronous and prone to temporary failures. In order to be robust and re-entrant, this canister keeps the state of every request as an explicit record in its stable memory. For every state, there is a transition function that attempts to make progress into the next state. If the transition fails, the original state remains as is, so that it can be retried. Transition functions are scheduled regularly with timers. 

### Lifecycle of a request

A user calls `migrate_canister`, providing the canister ID to migrate and the canister ID to replace. The request is validated using various calls to the registry and management canister. If validation fails, the user receives an error response. If validation suceeds, the result is a `Request` which uniquely identifies a migration request. This data is wrapped in a `RequestState` enum (in the `Accepted` variant) and saved in a stable set `REQUESTS`. A timed function picks up all items in `REQUESTS` that are in state `Accepted` and attempts to make progress into the next state.

As a `Request` progresses through the states, the corresponding `RequestState` variants accumulate data that is necessary to perform some future steps. E.g., `RequestState::StoppedAndReady` contains a `stopped_since` timestamp which will be necessary for a later transition to `RequestState::RestoredControllers`, which may only happen once 5 minutes since `stopped_since` have passed. 

This way, all data necessary to make progress is always available in the `RequestState` itself, making it easy to pick up and retry if it fails for a while. 

Despite the upfront request validation, not all error conditions can be ruled out by it or fixed by retrying. E.g., when the Migration Canister sets itself as the only controller, it might no longer be controller itself (if the user has manipulated the canister between validation and this moment). In such cases, the request enters a fail state, which enables the Migration Canister to clean up any undesirable situations (like the user having no control over their canisters). After cleanup, or after a request has been processed successfully, the `Request` is removed from the REQUESTS set and an event is recorded in `HISTORY`.
