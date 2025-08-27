# Migration Canister

This canister orchestrates the migration of a canister ID from one subnet to another. 

## Technical overview

Canister migration involves several crossnet calls, which makes the process highly asynchronous and prone to temporary failures. In order to be robust and re-entrant, this canister keeps the state of every request as an explicit record in its stable memory. For every state, there is a transition function that attempts to make progress into the next state. If the transition fails, the original state remains as is, so that it can be retried. Transition functions are scheduled regularly with timers. 

### Lifecycle of a request

A user calls `migrate_canister`, providing source and target canister IDs. ...
