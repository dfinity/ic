# Best Practices: Using panics in the Deterministic State Machine

## Scope of the document

The scope of this document is to provide guidance on how/when to use panics in the Deterministic State Machine (DSM). Such panics are very likely to get the DSM into a crash loop, so they should only be reserved for cases where this is the only correct behavior.

## Target audience

The audience for this document are primarily engineers working in the Execution and Message Routing teams. These are the most common contributors to the DSM but it might be relevant for other DFINITY engineers as well if they find themselves in the position of needing to change something in the DSM.

## Background

In software development, it’s a fairly common practice when writing a service to let it crash in cases where some invariant is violated or the binary has gotten into an otherwise unrecoverable state. Typically, letting the binary restart resolves issues (at least on the user facing side) while engineers can separately look into why the crash was hit in the first place and fix the root cause behind the scenes. However, this practice does not really work well when it comes to the DSM of the IC: if replicas hit such a case somewhere in the DSM, they will most likely keep hitting it as they will try to process the same messages again after they restart from the last checkpoint (given the IC’s nature as a deterministic replicated state machine).

If a subnet’s replicas enter such a crash loop, we typically need to perform a subnet recovery to get the subnet back up and running. This process can get quite lengthy and cumbersome (especially for subnets with large states), requires the involvement of a few teams (typically an expert from our side to perform any necessary fixes, the consensus team to perform the replay of state and the DRE team to coordinate replica version election and rollout on the affected subnet(s)) and so it should only be reserved for cases where there is really not much else that can be done.

In many cases having the replicas panic is rather extreme and we can get away with raising a [critical error](https://sourcegraph.com/github.com/dfinity/ic@d7cac19658a397f862f9e162c32ac02d21a3d77d/-/blob/rs/monitoring/metrics/src/registry.rs?L160) instead and letting the replicas continue running. The critical error will inform us about potential issues since it will page the FIT on call while the subnet continues to make progress without affecting end user experience.

The remainder of this document attempts to provide some guidance around when it’s ok to use panics or one should instead use the more forgiving critical error approach.

## Hard Invariants vs Soft Invariants

Code in `/rs/replicated_state` and `/rs/state_manager` uses the concept of hard vs soft invariants to decide when it’s necessary to panic and when it’s sufficient to raise a critical error or even just log an error message.

A [hard] invariant refers to a condition that (1) holds all the time, and (2) whose violation affects code correctness:

- We check these during deserialization and return an error (causing an upstream panic) if they don't hold.
- It is fine to assert/debug_assert (depending on how expensive these checks are) for them in production code.
- Proptests for these invariants are recommended, but can be skipped if there is consensus that they are not needed.

Soft invariants are a superset of hard invariants above:

- These include conditions that don't affect correctness of the code, but we still aim to uphold them at all times.
- They can be self healing, i.e., a violation will be fixed upon the next (few) modification(s).
- We never assert for them in production code, but may debug_assert and raise critical errors in case of a violation upon deserialization (cf. deserialization of `BlockmakerMetricsTimeSeries`).
- An example for a soft invariant is an upper bound on the number of elements in a data structure that maintains a sliding window of snapshots, where the actual number of snapshots does not affect correctness and we just want to ensure it does not grow indefinitely.

Important: we do not attempt to restore invariants or soft invariants upon deserializing as it could change the past and lead to divergence if only some replicas restart.

One important aspect to consider is state loading: it is relatively straightforward to preserve an invariant inside an in-memory data structure; but determinism often requires accepting values deserialized from a checkpoint. An invalid loaded value is OK for soft invariants, but must necessarily result in a panic for hard invariants.


## When should panics be used

Given the impact of panics in the DSM, it is important to limit their usage only to cases when they are absolutely necessary. Here’s a list of common cases where panics should be preferred:

- A system resource is exhausted. E.g. we do not have enough file descriptors and cannot create a new file in the State Manager. There’s not much we can do about it automatically, so we should panic in that case and handle it offline.
- An invariant in the implementation of a data structure is broken. In these cases, the data structure can perform any invariant checks internally in its implementation which is typically easier to verify/inspect if everything is contained within the data structure. An example of this is the [TaskQueue](https://sourcegraph.com/github.com/dfinity/ic@d7cac19658a397f862f9e162c32ac02d21a3d77d/-/blob/rs/replicated_state/src/canister_state/system_state.rs?L284) data structure. It’s also a good idea to have tests that cover any panics added and these should be typically safe to use. Alternatively, you should consider if debug_asserts would potentially be enough assuming we have good test coverage for the data structure.
- An invariant is broken which could lead to corrupted state or state divergence or some otherwise broken state that is difficult to recover from. In that case a panic should be preferred to avoid creating further more difficult to resolve issues. A good example of this would be the case where we handle [reserved cycles](https://sourcegraph.com/github.com/dfinity/ic@d7cac19658a397f862f9e162c32ac02d21a3d77d/-/blob/rs/system_api/src/sandbox_safe_system_state.rs?L514) in the system API.
- Hard invariants as defined above can result in panics when they get violated.


## When should panics be avoided

In some cases it’s best to avoid panics and instead either try to handle the errors or raise critical errors instead if it’s not easy to handle the error in place. debug_asserts are also highly encouraged for these cases.

- Wrong user input should never result in a replica panic.
- Invariants across components are very hard to maintain and keep up to date as code evolves. Avoid adding panics related to such invariants and use critical errors instead to make the teams aware about instances where we might hit an unexpected case (some exceptions might apply if the invariant could lead to corrupted state or be hard to recover from, but it really should be the last resort). A good example here is [load_canister_snapshot](https://www.google.com/url?q=https://sourcegraph.com/github.com/dfinity/ic@d7cac19658a397f862f9e162c32ac02d21a3d77d/-/blob/rs/execution_environment/src/canister_manager.rs?L2108-2126&sa=D&source=docs&ust=1733308984480434&usg=AOvVaw2K8SR6s3VMBOkSTryuhxga) where we check whether some scheduling precondition holds in the canister manager. In this case, using a panic would be very aggressive, stopping progress of the whole subnet for a bug related to canister snapshots. Returning an error back to the user and raising a critical error is the more appropriate handling of this case, containing the damage to some snapshots functionality only not working in case such a bug exists.
- Soft invariants as defined earlier should never result in a panic when they get violated. Instead raise a critical error or a debug_assert.
