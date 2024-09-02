# Best Practices: Making changes to Replicated State

## Scope of the document

The scope of this document is to provide guidance on best practices to consider when you find yourself in the position to make changes to the Replicated State (e.g. add a new field, remove an old one etc).

## Target audience

The audience for this document are engineers contributing to the Replicated State.

## Background

Most of the data included in the Replicated State is persisted to disk as part of the checkpointing mechanism of the Replica. We have selected protobuf as the format for the data that is persisted, so typically, we have mirror protobuf structs for the Rust data structures included in the Replicated State and we explicitly (de-)serialize to/from them during checkpoints.

Given the persistence of data and the fact that the Replica software is regularly upgraded, we need to ensure that new Replica versions can decode existing data in the checkpoints. This is the **backward compatibility** requirement. Furthermore, because we want to be able to rollback a Replica version in case of a bug or any other problem with it, it’s also important that the previous Replica version can understand the data persisted by the next. This is the **forward compatibility** requirement.

Requiring both backward and forward compatibility of any changes made to the Replicated State makes it more challenging to perform any changes to the Replicated State but following a small set of best practices can make this experience as painless as possible.

## Handling changes to Enums

### Adding a new Enum

If you’re adding a new enum to the Replicated State, you can do so in a single step as long as (a) rolling back to a previous version will ignore it and (b) ignoring it is the desired behavior. If (a) or (b) does not hold, then you’d need to introduce the enum in the first step and only after this has been rolled out fully to all subnets, start using it in production code in a second step. [See note on rolling back/forward](#note-on-rolling-backforward).

Additionally, ensure that you include protobuf roundtrip encoding/decoding tests against its Rust mirror enum and also compatibility tests that confirm the encoding to raw numbers is the expected one if this is a unit Enum (structured enums are much harder to write such compatibility tests for and can be skipped). See an example of these two tests [here](https://sourcegraph.com/github.com/dfinity/ic@1c221e6c4c1fe8fedd039505dd46760e24af7b22/-/blob/rs/replicated_state/src/canister_state/tests.rs?L605-L627).

### Changing an existing Enum

If you make changes to an existing enum, you need to ensure that said changes are compatible across replica releases which might require some special handling. Specifically, changes to enums need to be rolled out in stages, across multiple replica releases. One must ensure that the release with the first stage of the change is deployed to each subnet before proceeding with the second stage. [See note on rolling back/forward](#note-on-rolling-backforward).

- If you are removing a variant, in the first stage change the production code to (1) no longer use said variant (except its definition and conversion logic) and (2) ensure that pre-existing instances of said variant in the Replicated state will be (implicitly or explicitly) be removed as well; only once this change has been deployed to all subnets, in the second phase, remove the variant and update any relevant tests.
- If you are adding a variant, in the first stage define the variant and necessary conversion logic, without using it anywhere (and update any relevant tests); once the replica release has been deployed to all subnets, it’s safe to start using the new variant in the production code.
- If you are remapping the numeric code behind a variant, you must do it as concurrent removal and addition operations (see above). You can also rename the variant you are removing to `Deprecated<Name>` as part of the first step, so you can concurrently define the new variant and preserve the name.

## Handling changes to Structs

### Adding a new Struct

If you are adding a new struct to the Replicated State, you can do so in a single step as long as (a) rolling back to a previous version will ignore it and (b) ignoring it is the desired behavior. If (a) or (b) does not hold, then you’d need to introduce the struct in the first step and only after this has been rolled out fully to all subnets, start using it in production code in a second step. [See note on rolling back/forward](#note-on-rolling-backforward).

Additionally, ensure that you include protobuf roundtrip encoding/decoding tests against its Rust mirror struct. See an example of this [here](https://sourcegraph.com/github.com/dfinity/ic@1c221e6c4c1fe8fedd039505dd46760e24af7b22/-/blob/rs/replicated_state/src/canister_state/tests.rs?L629-L642).

### Changing an existing Struct

If you make changes to an existing struct, you need to ensure that said changes are compatible across replica releases. Changes might need to be rolled out in stages, across multiple replica releases depending on the nature of the change. One must ensure that the release with the first stage of the change is deployed to each subnet before proceeding with the second stage. [See note on rolling back/forward](#note-on-rolling-backforward).

- If you’re removing a field from the struct, in the first stage change the production code to (1) no longer use said field (except its definition and conversion logic) and (2) ensure that pre-existing instances of said field in the Replicated state will be (implicitly or explicitly) be removed as well; only once this change has been deployed to all subnets, in the second phase, remove the field and update any relevant tests.
- If you are adding a field to a struct, in the first stage define the field and necessary conversion logic, without using it anywhere (and update relevant tests); once the replica release has been deployed to all subnets, it’s safe to start using the new field in the production code.
- If you want to replace an existing field (e.g. the type needs to change), you will need to treat it as concurrent removal and addition operations (see above). In the first stage, you can add the new field and populate both old and new fields using the value of the old field. You can also add logic to try to decode from the old field if set, otherwise use the new field to decode from the checkpoint. Once this change has been deployed to all subnets, you can remove the old field and any related logic and only keep the new one.

## Creating Merge Requests to modify Replicated State

All changes to the Replicated State should be made in separate, concise merge requests. These requests must include clear descriptions outlining forward and backward compatibility considerations. An example of this format can be found [here](https://github.com/dfinity/ic/commit/bc0117af241712207e04649296eb159f5e82922d).

## Note on rolling back/forward

Note that because we assume we never roll back or forward more than one release at a time, this implies that we have to be reasonably confident that each step in a multi-stage rollout will not need to be rolled back before proceeding with the next step.
