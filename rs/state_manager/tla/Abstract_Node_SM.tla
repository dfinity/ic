A model of the state machine of a single node (replica), and the local transitions 
that it can take - that is, transitions that don't involve the other subnet nodes.
---- MODULE Abstract_Node_SM ----
EXTENDS TLC, Naturals, FiniteSets, FiniteSetsExt, Common_Defs, Util

VARIABLE 
    \* In-memory states
    \* In the implementation, it should correspond to
    \* https://sourcegraph.com/github.com/dfinity/ic@f0adf9a7a07487906e0600a39ca0673a94d0e7dc/-/blob/rs/state_manager/src/lib.rs?L689
    states,
    \* Checkpoints (persisted states)
    \* In the implementation, the checkpoints are stored as described here:
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/state_layout/src/state_layout.rs?L287:5
    checkpoints,
    \* Manifests (hashes of checkpoints)
    \* In the implementation, they correspond to the BundledManifest stored in the StatesMetadata struct:
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/state_manager/src/lib.rs?L686
    \* Note that they are also stored on the disk in the states_metadata.pbuf; however, some of them may not be loaded into memory on startup.
    manifests,
    \* Subnet certifications that the node has
    \* These correspond to the certifications in the CertificationPool:
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/interfaces/src/certification.rs?L30:5
    local_certifications,
    \* CUPs that the node has
    \* These correspond to the CUPs in the validated ConsensusPool:
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/interfaces/src/consensus_pool.rs?L228
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/interfaces/src/consensus_pool.rs?L150:5
    local_cups,
    \* Finalized blocks that the node has
    \* These correspond to the finalized blocks in the ConsensusPool
    \* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/consensus/utils/src/pool_reader.rs?L292:9
    local_blocks,
    \* Auxiliary modeling variable; whether the last step was a crash. This is used to easily distinguish crashes from
    \* other steps; we can't uphold our guarantees if the node keeps crashing infinitely often. 
    freshly_crashed,
    \* Auxiliary variables that cache information so that TLC doesn't recompute it. 
    aux_manifest_heights,
    aux_next_state_heights,
    aux_checkpoint_heights

CONSTANT
    \* Whether the model allows the replica to diverge (in limited ways). 
    \* Set this (in a configuration file or an instance file) appropriately for the behavior you want to analyze.
    DIVERGENCE_ENABLED

vars == << states, checkpoints, manifests, local_certifications, local_cups, local_blocks, aux_manifest_heights, aux_next_state_heights, aux_checkpoint_heights, freshly_crashed >>

Certified_Checkpoints == 
    GENESIS_HEIGHT :> genesis_state @@
        Intersect_Funs(checkpoints, local_cups)

\* The highest state we could compute in a verifiable way based on just the local data
Certified_Tip == Max({GENESIS_HEIGHT} \union {
    h \in HEIGHTS: \E h2 \in GENESIS_HEIGHT..h: 
        /\ h2+1..h \subseteq DOMAIN local_blocks
        /\ h2 \in DOMAIN Certified_Checkpoints
    })

\* We express some of the action guards in two variants: a "simple" guard which captures the meaning, and the actually
\* used guard that uses some pre-computed information to speed up TLC. The equality of the two guards
\* is asserted in the Optimization_Correctness property.
\* Concretely, we can compute only the successor state of the highest state we currently have, 
\* and only assuming that we already have the corresponding block. 
Compute_Next_State_Heights_Simple ==
    {Max(DOMAIN states) + 1} \intersect DOMAIN local_blocks
Compute_Next_State_Heights == aux_next_state_heights

\* Action: compute the next state based on a block. This models the commit_and_certify call here:
\* https://sourcegraph.com/github.com/dfinity/ic@914b617de5314f76c62b37171f1d9c41588cc2fb/-/blob/rs/messaging/src/message_routing.rs?L942
Compute_Next_State(new_height, new_state) ==
  LET 
    previous_height == new_height - 1
  IN
    /\ new_height \in Compute_Next_State_Heights
    \* If the preceding height is a checkpoint height, we block producing the new state until we have a checkpoint.
    \* This models the current process where checkpointing blocks the state machine.
    /\  IS_CHECKPOINT_HEIGHT(previous_height)
        => previous_height \in DOMAIN checkpoints
    /\ 
        \* Correct execution
        \/ new_state = Execute_Block(states[previous_height], local_blocks[new_height].payload)
        \* Divergence in execution; pick an arbitrary state
        \/
            /\ DIVERGENCE_ENABLED
            /\ new_state \in STATES
    /\ states' = new_height :> new_state @@ states
    /\ aux_next_state_heights' = IF new_height = MAX_HEIGHT \/ new_height+1 \notin DOMAIN local_blocks THEN {} ELSE {new_height + 1}
    /\ aux_checkpoint_heights' = aux_checkpoint_heights \union IF 
            IS_CHECKPOINT_HEIGHT(new_height) /\ new_height > Max(DOMAIN checkpoints) 
            THEN {new_height} 
            ELSE {}
    /\ UNCHANGED << checkpoints, manifests, local_blocks, local_certifications, local_cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_manifest_heights
    /\ UNCHANGED genesis_state

\* We express some of the action guards in two variants: a "simple" guard which
\* captures the meaning, and the actually used guard that uses some pre-computed
\* information to speed up TLC. The equality of the two guards is asserted in
\* the Optimization_Correctness property.
\*
\* We allow the system to compute any checkpoint for any state that we already
\* have, as long as we don't already have the corresponding checkpoint.
\*
\* TODO (MR-522): 
\*       The implementation won't compute a checkpoint unless a manifest for the
\*       previous checkpoint is available:
\*       https://sourcegraph.com/github.com/dfinity/ic@914b617de5314f76c62b37171f1d9c41588cc2fb/-/blob/rs/state_manager/src/tip.rs?L148
\*       That is, checkpoints are never computed in parallel. We could make use
\*       of this to minimize the number of states. Also, we could in theory miss some
\*       deadlocks in the model as we might "get out of jail" by computing a checkpoint
\*       that's not actually done by the implementation.
Compute_Checkpoint_Heights_Simple ==
    (DOMAIN states \intersect All_Checkpoint_Heights) \ DOMAIN checkpoints

Compute_Checkpoint_Heights ==
    aux_checkpoint_heights

\* Action: compute a checkpoint based on an existing state. Corresponds to
\* https://sourcegraph.com/github.com/dfinity/ic@914b617de5314f76c62b37171f1d9c41588cc2fb/-/blob/rs/state_manager/src/lib.rs?L2993
Compute_Checkpoint(height) ==
    /\ height \in Compute_Checkpoint_Heights
    /\ checkpoints' = height :> states[height] @@ checkpoints
    /\ aux_manifest_heights' = aux_manifest_heights \union {height}
    /\ aux_checkpoint_heights' = aux_checkpoint_heights \ {height}
    /\ UNCHANGED << states, manifests, local_blocks, local_certifications, local_cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_next_state_heights
    /\ UNCHANGED genesis_state

\* We express some of the action guards in two variants: a "simple" guard which
\* captures the meaning, and the actually used guard that uses some pre-computed
\* information to speed up TLC. The equality of the two guards is asserted in
\* the Optimization_Correctness property.
\*
\* TODO (MR-522): 
\*       The implementation uses a queue for manifest computation, i.e., the order
\*       is not arbitrary. Do we want to enforce that in the model? Otherwise there
\*       could in theory be deadlocks that we wouldn't catch.
Compute_Manifest_Heights_Simple ==
    DOMAIN checkpoints \ DOMAIN manifests
Compute_Manifest_Heights == aux_manifest_heights

\* Save the computed manifest. Corresponds to:
\* https://sourcegraph.com/github.com/dfinity/ic@914b617de5314f76c62b37171f1d9c41588cc2fb/-/blob/rs/state_manager/src/tip.rs?L798:5
\* In the implementation, the manifest and the "bundled manifest" are computed here:
\* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/state_manager/src/manifest.rs?L825:1
\* resp. here:
\* https://sourcegraph.com/github.com/dfinity/ic@f7eb149d02031eca2a092d9dc3bbffa67b804dc5/-/blob/rs/state_manager/src/manifest.rs?L1198:12
\* @type: $state -> $hash;
Compute_Manifest(height) ==
    /\ height \in Compute_Manifest_Heights_Simple
    \* Possible divergence in manifest computation; compute an arbitrary state hash
    /\ \E m_hash \in IF DIVERGENCE_ENABLED THEN [STATES -> HASHES] ELSE {correct_m_hash}: 
            /\
                \/
                    /\ height \in DOMAIN local_cups => 
                        m_hash[checkpoints[height]] = local_cups[height]
                    /\ checkpoints' = checkpoints
                    /\ manifests' = height :> m_hash[checkpoints[height]] @@ manifests
                    /\ aux_manifest_heights' = aux_manifest_heights \ {height} 
                    /\ UNCHANGED aux_checkpoint_heights 
                \/ 
                    \* Detected divergence; remove the corresponding checkpoint and delete the computed manifest
                    /\ height \in DOMAIN local_cups
                    /\ m_hash[checkpoints[height]] # local_cups[height]
                    /\ checkpoints' = Remove_Arguments(checkpoints, {height})
                    /\ aux_checkpoint_heights' = aux_checkpoint_heights \union IF height \in DOMAIN states THEN {height} ELSE {}
                    /\ aux_manifest_heights' = aux_manifest_heights \ {height} 
                    /\ UNCHANGED manifests
    /\ UNCHANGED << states, local_blocks, local_certifications, local_cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_next_state_heights
    /\ UNCHANGED genesis_state

Garbage_Collect_Heights ==
    DOMAIN local_cups
\* Action: garbage collect data that is no longer needed
\* Note: this action is no longer used in the combined model, where garbage collection is done immediately
\* when receiving a CUP, in order to reduce the state space. Still keeping it around to make the single-node
\* model more self contained.
Garbage_Collect(below_height) ==
    /\ below_height \in Garbage_Collect_Heights
    /\ states' = Remove_Arguments(states, GENESIS_HEIGHT+1 .. below_height-1)
    /\ local_blocks' = Remove_Arguments(local_blocks, GENESIS_HEIGHT+1 .. below_height - 1)
    /\ local_certifications' = local_certifications \ GENESIS_HEIGHT+1 .. below_height-1
    /\ local_cups' = Remove_Arguments(local_cups, GENESIS_HEIGHT+1 .. below_height-1)
    \* NOTE: in reality, we will leave around at least one (non-genesis) checkpoint.
    /\ checkpoints' = Remove_Arguments(checkpoints, GENESIS_HEIGHT+1 .. below_height-1)
    /\ manifests' = Remove_Arguments(manifests, GENESIS_HEIGHT+1 .. below_height-1)
    /\ aux_checkpoint_heights' = aux_checkpoint_heights \ {h \in aux_checkpoint_heights: h < below_height}
    /\ aux_next_state_heights' = aux_next_state_heights \ {h \in aux_next_state_heights: h <= below_height}
    /\ aux_manifest_heights' = aux_manifest_heights \ {h \in aux_manifest_heights: h < below_height}
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state

\* Action: crash the node, losing the in-memory data
Crash_And_Restart ==
    \* At startup, the state manager archives checkpoints below the provided starting height
    /\ LET 
            \* The starting height is determined here:
            \* https://sourcegraph.com/github.com/dfinity/ic@88777d653977c10c6596ab9bbb0922e8c450d0af/-/blob/rs/interfaces/src/consensus_pool.rs?L317
            \* Note: this is not exactly the same as in the code; there, to determine the certified_height above, we first take the higher of the following two blocks:
            \* 1. the last finalized block
            \* 2. the summary block contained in last CUP (this is embedded in the CUP itself)
            \* then we take the validation context of the whichever block we pick above
            \* https://sourcegraph.com/github.com/dfinity/ic@579e1558ba7e03d6e786593fd6ed14dcd851ffae/-/blob/rs/artifact_pool/src/consensus_pool_cache.rs?L251
            \* However, this doesn't matter: the CUP has a higher height than the validation context of its summary block, so taking
            \* the max with the CUP height here is sufficient.
            last_vc == IF DOMAIN local_blocks = {} THEN GENESIS_HEIGHT ELSE local_blocks[Max(DOMAIN local_blocks)].validation_context
            starting_height == Max(DOMAIN local_cups \union {last_vc})
        IN
            \* The archiving is done here:
            \* https://sourcegraph.com/github.com/dfinity/ic@579e1558ba7e03d6e786593fd6ed14dcd851ffae/-/blob/rs/state_manager/src/lib.rs?L1372
            /\ checkpoints' = Restrict(checkpoints, GENESIS_HEIGHT..starting_height)
            \* The manifest deletion for archived checkpoint is implicit, in that we just don't populate the corresponding StatesMetadata because
            \* the checkpointed state is no longer in the `states` here:
            \* https://sourcegraph.com/github.com/dfinity/ic@579e1558ba7e03d6e786593fd6ed14dcd851ffae/-/blob/rs/state_manager/src/lib.rs?L1468
            /\ manifests' = Restrict(manifests, GENESIS_HEIGHT..starting_height)
            \* Repopulate the states from checkpoints; we load one state for each checkpoint at or below the starting height
            \* https://sourcegraph.com/github.com/dfinity/ic@579e1558ba7e03d6e786593fd6ed14dcd851ffae/-/blob/rs/state_manager/src/lib.rs?L1426
            /\ states' = Restrict(checkpoints, GENESIS_HEIGHT..starting_height)
    /\ aux_next_state_heights' = LET next == Max(DOMAIN states') + 1 IN
        IF next \in DOMAIN local_blocks THEN {next} ELSE {}
    /\ aux_checkpoint_heights' = {}
    /\ freshly_crashed' = TRUE
    /\ UNCHANGED aux_manifest_heights
    /\ UNCHANGED << local_blocks, local_certifications, local_cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state

Remove_Inmemory_States_Below(s, height) ==
    [h \in {i \in DOMAIN s: i = GENESIS_HEIGHT \/ i >= height } |-> s[h]]

Init ==
    /\ genesis_state \in STATES
    /\ states = GENESIS_HEIGHT :> genesis_state
    /\ checkpoints = GENESIS_HEIGHT :> genesis_state
    /\ manifests = GENESIS_HEIGHT :> correct_m_hash[genesis_state]
    /\ local_blocks = [x \in {} |-> {}]
    /\ local_certifications = {GENESIS_HEIGHT}
    /\ local_cups = GENESIS_HEIGHT :> genesis_state
    /\ Init_Common
    /\ aux_manifest_heights = {}
    /\ aux_next_state_heights = {}
    /\ aux_checkpoint_heights = {}
    /\ freshly_crashed = FALSE

Next ==
    \/
      /\
        \/ \E h \in Compute_Next_State_Heights, s \in STATES: Compute_Next_State(h, s)
        \/ \E h \in Compute_Checkpoint_Heights: Compute_Checkpoint(h)
        \/ \E h \in Garbage_Collect_Heights: Garbage_Collect(h)
        \/ \E h \in aux_manifest_heights: Compute_Manifest(h)
      /\ freshly_crashed' = FALSE
    \/ Crash_And_Restart

Fairness ==
    /\ WF_vars(
        \/ \E h \in Compute_Next_State_Heights, s \in STATES: Compute_Next_State(h, s)
        \/ \E h \in Compute_Checkpoint_Heights: Compute_Checkpoint(h)
        \/ \E h \in Compute_Manifest_Heights:  Compute_Manifest(h)
     )

\* We state that the optimized guards are always the same as the "simple" guards.
Optimization_Correctness ==
    /\ Compute_Checkpoint_Heights = Compute_Checkpoint_Heights_Simple
    /\ Compute_Next_State_Heights = Compute_Next_State_Heights_Simple
    /\ Compute_Manifest_Heights = Compute_Manifest_Heights_Simple

====