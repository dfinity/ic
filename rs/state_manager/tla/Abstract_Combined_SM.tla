This is an abstract model of the how a replica's state manager behaves in relation to the replica's subnet.

The subnet is represented just through its artifacts: finalized blocks, certifications and catch-up packages (CUPs). 
Such an artifact in the model roughly corresponds to the actual artifact existing somewhere on some subnet node.
The state manager is represented through its local states, checkpoints, manifests, as well as the subnet artifacts that the replica has obtained.

The model is a bit more complicated than it could be, since we had to optimize it for analysis performance.
For example, some of the guards are expressed through a precomputed variable, rather than a predicate, 
to avoid having to compute the predicate in the next-state relation. The equality with the predicate is
also asserted as a separate invariant and it can be checked separately.

One non-obvious element of the model is the restriction of subnet actions. Namely, we want to allow a honest 
replica to "fall behind", where the other replicas can produce artifacts such as blocks and CUPs without the replica.
This can happen because an attacker can at first cooperate with the other replicas to produce of such artifacts.
However, the attacker could at any point stop cooperating; the subnet then can't produce any new artifacts without
the replica's input. We model this by adding a `needed_for_progress` variable that can be toggled by the environment
(when it's toggled on, the attacker effectively chooses to go from cooperating to non-cooperating).

Similarly, subnet artifacts may become unavailable with time, as the replicas may garbage collect them.
Still, even if all honest replicas garbage collect an artifact, the attacker can still provide it.
We model this by adding a `can_obtain_stale_artifacts` variable that can be toggled by the environment (i.e., the attacker).
When it's on, the replica can obtain any artifact that was ever produced by the subnet.
When it's off, the replica can only obtain artifacts that are still available to the honest replicas.
This way, if the attacker can lead the replica to a bad state or violate liveness by providing old
artifacts, it can toggle the switch to on, deliver whatever it needs to induce the bad state, and then turn
it off again to prevent the replica from obtaining other stale artifacts.

Analyze this with Optimized_Abstract_Combined_SM.cfg (in VSCode: choose TLA+: Check model with TLC using non-default config).

---- MODULE Abstract_Combined_SM ----
EXTENDS TLC, Naturals, Sequences, FiniteSets, FiniteSetsExt, Common_Defs, Util 

VARIABLE 
    \* Subnet variables (inherited from Abstract_Replicated_SM)
    blocks,
    certifications,
    cups,
    aux_next_block_height,
    aux_next_cup_height,
    aux_possible_certifications,
    \* Local node variables (inherited from Abstract_Node_SM)
    states,
    checkpoints,
    manifests,
    local_certifications,
    local_cups,
    local_blocks,
    freshly_crashed,
    aux_manifest_heights,
    aux_next_state_heights,
    aux_checkpoint_heights,
    \* Controls whether the replica is needed for progress
    needed_for_progress,
    \* Records which CUPs the replica has contributed to.
    \* Used for specifying the safety properties.
    contributed,
    \* 
    can_obtain_stale_artifacts

CONSTANT DIVERGENCE_ENABLED

Subnet_SM == INSTANCE Abstract_Replicated_SM
Node_SM == INSTANCE Abstract_Node_SM

Subnet_vars == << blocks, certifications, cups, aux_next_block_height, aux_next_cup_height, aux_possible_certifications >>
Node_vars == << states, checkpoints, manifests, local_certifications, local_cups, local_blocks, aux_manifest_heights, aux_next_state_heights, aux_checkpoint_heights >>
vars == << blocks, certifications, cups, states, checkpoints, manifests, local_blocks, local_certifications, local_cups, needed_for_progress, exec_f, aux_manifest_heights, aux_next_state_heights, aux_next_block_height, aux_next_cup_height, aux_possible_certifications, aux_checkpoint_heights, genesis_state, contributed, can_obtain_stale_artifacts, freshly_crashed >>

\* Controls which blocks the replica can finalize - either by collecting the
\* block and the finalization shares itself, or by receiving a finalized block
\* from the subnet.
\* We assume that the replica won't finalize blocks lower than a CUP that it already has;
\* it doesn't process such finalizations here:
\* https://sourcegraph.com/github.com/dfinity/ic@d2679ab112ee7682b9e3c8836d3a9d38e88c047e/-/blob/rs/consensus/src/consensus/validator.rs?L682
\* Moreover, it will either accept a block that's one higher than the highest (finalized) block
\* it already has, or a block following the highest checkpoint and CUP that it has.
Accept_Block_Heights == 
    LET
        candidate_blocks == IF can_obtain_stale_artifacts THEN blocks ELSE Subnet_SM!Guaranteed_Available_Blocks
    IN
        { 
        h \in DOMAIN candidate_blocks \ (DOMAIN local_blocks \union GENESIS_HEIGHT+1..Max(DOMAIN local_cups)):
            /\ 
                \/ DOMAIN local_blocks = {}
                \/ h > Max(DOMAIN local_blocks)
            /\ 
                \/ h - 1 = Max(DOMAIN Node_SM!Certified_Checkpoints)
                \/ h - 1 \in DOMAIN local_blocks
        }
\* Action: accept a finalized subnet block
Accept_Block(height) ==
    /\ height \in Accept_Block_Heights
    /\ blocks[height].validation_context \in local_certifications
    /\ local_blocks' = height :> blocks[height] @@ local_blocks
    \* Models
    \* https://sourcegraph.com/github.com/dfinity/ic@d129c2010dc69de2dedda06feab250787eebc139/-/blob/rs/consensus/src/consensus/purger.rs?L91
    /\ IF DOMAIN local_blocks = {} \/ blocks[height].validation_context > Max({b.validation_context : b \in Range(local_blocks)})
        THEN 
            /\ states' = Node_SM!Remove_Inmemory_States_Below(states, Min({blocks[height].validation_context, Max(DOMAIN states)}))
            /\ aux_checkpoint_heights' = aux_checkpoint_heights \ 
                    {h \in aux_checkpoint_heights: h < blocks[height].validation_context}
        ELSE UNCHANGED << states, aux_checkpoint_heights >>
    /\ aux_next_state_heights' = IF height - 1 = Max(DOMAIN states) THEN {height} ELSE aux_next_state_heights
    /\ UNCHANGED << checkpoints, manifests, local_certifications, local_cups >>
    /\ UNCHANGED aux_manifest_heights
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* We can accept any available CUP that's higher than what we currently have.
Accept_CUP_Heights == 
    LET
        candidate_cups == IF can_obtain_stale_artifacts THEN cups ELSE Subnet_SM!Guaranteed_Available_CUPs
    IN
        {h \in DOMAIN candidate_cups: h > Max(DOMAIN local_cups)}

\* Action: accept a subnet CUP, either by aggregating the shares or receiving it from others.
\* Done here in the code:
\* https://sourcegraph.com/github.com/dfinity/ic@50f45debb8f9409f98940c3914dbc4b45eb5c485/-/blob/rs/consensus/src/consensus/validator.rs?L1318:5
\* https://sourcegraph.com/github.com/dfinity/ic@50f45debb8f9409f98940c3914dbc4b45eb5c485/-/blob/rs/consensus/src/consensus/share_aggregator.rs?L136:8
\* Note that accompanying garbage collection can also be triggered by other events in the code, such as
\* accepting certifications:
\* https://sourcegraph.com/github.com/dfinity/ic@50f45debb8f9409f98940c3914dbc4b45eb5c485/-/blob/rs/consensus/src/consensus/purger.rs?L94:13
\*
\* Note: this is a slight underapproximation of GC. In reality, we don't trigger it only on CUPs, but we also have remove_inmemory_states_below
\*       in the state manager:
\*       https://sourcegraph.com/github.com/dfinity/ic@5281b55657a01273d8ec236d2838669eb6198cc5/-/blob/rs/consensus/src/consensus/purger.rs?L274 
\* However, in the analysis that we performed, this shouldn't matter much
Accept_CUP(height) ==
    /\ height \in Accept_CUP_Heights
    \* Add the CUP and garbage collect.
    \* We spell the GC out here; this copies a lot of Node_SM!Garbage_Collect, but there
    \* doesn't seem to be a nice way to reuse that definition.
    /\ local_cups' = height :> cups[height] 
        @@ Remove_Arguments(local_cups, GENESIS_HEIGHT+1 .. height-1)
    /\ states' = Remove_Arguments(states, GENESIS_HEIGHT+1 .. height-1)
    /\ local_blocks' = Remove_Arguments(local_blocks, GENESIS_HEIGHT+1 .. height - 1)
    /\ local_certifications' = local_certifications \ GENESIS_HEIGHT+1 .. height-1
    \* Note: in reality, we will leave around at least one (non-genesis) checkpoint if we have one.
    \* But this is just an optimization, to be able to sync the state deltas instead of the full state,
    \* and it shouldn't affect the model.
    /\ checkpoints' = Remove_Arguments(checkpoints, GENESIS_HEIGHT+1 .. height-1)
    /\ manifests' = Remove_Arguments(manifests, GENESIS_HEIGHT+1 .. height-1)
    /\ aux_checkpoint_heights' = aux_checkpoint_heights \ {h \in aux_checkpoint_heights: h < height}
    /\ aux_next_state_heights' = aux_next_state_heights \ {h \in aux_next_state_heights: h <= height}
    /\ aux_manifest_heights' = aux_manifest_heights \ {h \in aux_manifest_heights: h < height}
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* We can accept certifications in any order, as long as we have the corresponding state.
Accept_Certification_Heights == 
    LET
        candidate_certifications == IF can_obtain_stale_artifacts THEN certifications ELSE Subnet_SM!Guaranteed_Available_Certifications
    IN
        (DOMAIN states \intersect DOMAIN candidate_certifications) \ local_certifications

\* Action: accept a subnet certification.
\* Models the following code:
\* https://sourcegraph.com/github.com/dfinity/ic@50f45debb8f9409f98940c3914dbc4b45eb5c485/-/blob/rs/consensus/src/certification/certifier.rs?L188
Accept_Certification(height) ==
    /\ height \in Accept_Certification_Heights
    /\ certifications[height] = states[height]
    /\ local_certifications' = local_certifications \union {height}
    /\ UNCHANGED << states, checkpoints, manifests, local_cups, local_blocks >>
    /\ UNCHANGED aux_manifest_heights
    /\ UNCHANGED aux_next_state_heights
    /\ UNCHANGED aux_checkpoint_heights 
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* In the model, we can only sync the state corresponding to the latest CUP that we have.
\* NOTE: the implementation can probably end up syncing older states too; while we invoke state sync immediately when we receive a CUP:
\*      https://sourcegraph.com/github.com/dfinity/ic@21a45c3853f94d0e85f036e99a79453e44fcd156/-/blob/rs/consensus/src/consensus/catchup_package_maker.rs?L117
\*      and we then proceed to ignore the old state in the should_download function:
\*      https://sourcegraph.com/github.com/dfinity/ic@21a45c3853f94d0e85f036e99a79453e44fcd156/-/blob/rs/state_manager/src/state_sync.rs?L189
\*      (given that EXTRA_CHECKPOINTS_TO_KEEP is 0), it's not obvious that we couldn't have a weird scheduling where we
\*      get a new CUP, but then still P2P immediately delivers an old checkpoint. Still it's hard to imagine this being a problem, so in the interest
\*      of keeping model checking tractable, we'll ignore this.
Sync_State_Heights == 
    LET 
        max_cup == Max(DOMAIN local_cups) 
        candidate_cups == IF can_obtain_stale_artifacts THEN cups ELSE Subnet_SM!Guaranteed_Available_CUPs
    IN
    IF 
      /\ max_cup \in DOMAIN candidate_cups
      /\ 
        \/ max_cup > Max(DOMAIN checkpoints \union DOMAIN states \union DOMAIN local_blocks)
        \/ 
            /\ max_cup \in DOMAIN manifests
            /\ manifests[max_cup] # cups[max_cup] 
    THEN {max_cup}
    ELSE {}

\* Action: sync the local state from a remote state
\* Models the following code:
\* https://sourcegraph.com/github.com/dfinity/ic@50f45debb8f9409f98940c3914dbc4b45eb5c485/-/blob/rs/consensus/src/consensus/catchup_package_maker.rs?L117:9
Sync_State(new_height, new_state) ==
    /\ new_height \in Sync_State_Heights
    /\ cups[new_height] = new_state
    /\ states' = new_height :> new_state @@ states
    /\ aux_next_state_heights' = IF new_height + 1 \in DOMAIN local_blocks /\ new_height + 1 > Max(DOMAIN states)  
        THEN {new_height + 1} 
        ELSE {h \in aux_next_state_heights : h > new_height}
    /\ checkpoints' = new_height :> new_state @@ checkpoints
    /\ manifests' = new_height :> new_state @@ manifests
    /\ aux_checkpoint_heights' = aux_checkpoint_heights \ GENESIS_HEIGHT..new_height
    \* /\ aux_manifest_heights' = aux_manifest_heights \union {new_height}
    /\ aux_manifest_heights' = aux_manifest_heights \ {new_height}
    /\ UNCHANGED << needed_for_progress, local_blocks, local_certifications, local_cups >>
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* The environment (attacker) can choose whether the replica is needed to produce any
\* further subnet artifacts.
Toggle_Needed_For_Progress ==
    /\ needed_for_progress' = ~needed_for_progress
    /\ UNCHANGED aux_manifest_heights
    /\ UNCHANGED Node_vars
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* The environment (attacker) can choose whether it makes stale artifacts available
\* to the replica.
Toggle_Stale_Artifact_Availability ==
    /\ can_obtain_stale_artifacts' = ~can_obtain_stale_artifacts
    /\ UNCHANGED Node_vars
    /\ UNCHANGED Subnet_vars
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state
    /\ UNCHANGED contributed
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED aux_manifest_heights
    /\ freshly_crashed' = FALSE

\* Whether the node will issue a CUP share for this height and state
Can_Contribute_To_CUP(height, state) ==
    /\ height \notin DOMAIN local_cups
    /\ height \in DOMAIN manifests
    /\ manifests[height] = state
    /\
        \E h2 \in height+1..MAX_HEIGHT:
            /\ h2 \in DOMAIN local_blocks
            /\ local_blocks[h2].validation_context >= height

\* Action: the subnet produces a CUP. May require the node to contribute a share.
Conditionally_Produce_CUP(height, state) ==
    /\ needed_for_progress => 
          /\ Can_Contribute_To_CUP(height, state)
          \* This doesn't quite work with divergence
          \* /\ contributed' = height :> state @@ contributed
          \* This works even with divergence
          /\ contributed' = height :> checkpoints[height] @@ contributed
    /\ ~needed_for_progress => 
          /\ contributed' = contributed
    /\ Subnet_SM!Produce_CUP(height, state)
    /\ UNCHANGED Node_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* Whether the node can contribute to finalizing this block
Can_Contribute_To_Block(height, payload, validation_context) ==
    /\ height \notin DOMAIN local_blocks
    /\ Node_SM!Certified_Tip = height - 1
    /\ validation_context >= Max({GENESIS_HEIGHT} \union local_certifications)
    /\ UNCHANGED can_obtain_stale_artifacts

\* Action: the subnet finalizes a block. May require the node to contribute a
\* finalization share.
Conditionally_Produce_Block(height, payload, validation_context) ==
    /\
        needed_for_progress =>
            Can_Contribute_To_Block(height, payload, validation_context)
    /\ Subnet_SM!Produce_Block(height, payload, validation_context)
    /\ UNCHANGED Node_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

\* Whether the node can contribute a certification share for this state.
Can_Contribute_To_Certification(height, state) ==
    /\ height \notin local_certifications
    /\ height \in DOMAIN states
    /\ states[height] = state
    /\ height - 1 \in local_certifications

\* Action: the subnet certifies a state. May require the node to contribute a
\* certification share.
Conditionally_Certify_State(height, state) ==
    /\
        needed_for_progress =>
            Can_Contribute_To_Certification(height, state)
    /\ Subnet_SM!Certify_State(height, state)
    /\ UNCHANGED Node_vars
    /\ UNCHANGED needed_for_progress
    /\ UNCHANGED contributed
    /\ UNCHANGED can_obtain_stale_artifacts
    /\ freshly_crashed' = FALSE

Init ==
    /\ Subnet_SM!Init
    /\ Node_SM!Init
    /\ needed_for_progress = FALSE
    /\ contributed = [x \in {} |-> {}]
    /\ can_obtain_stale_artifacts = TRUE

\* To check that we don't deadlock, we'll split the actions into the environment ones,
\* and the system ones.
Environment_Actions ==
    \/ Node_SM!Crash_And_Restart /\ UNCHANGED Subnet_vars /\ UNCHANGED needed_for_progress /\ UNCHANGED contributed /\ UNCHANGED can_obtain_stale_artifacts
    \/ Toggle_Needed_For_Progress
    \/ Toggle_Stale_Artifact_Availability

System_Actions ==
    \/ freshly_crashed' = FALSE /\ \E h \in Node_SM!Compute_Next_State_Heights, s \in STATES: Node_SM!Compute_Next_State(h, s) /\ UNCHANGED Subnet_vars /\ UNCHANGED needed_for_progress /\ UNCHANGED contributed /\ UNCHANGED can_obtain_stale_artifacts
    \/ freshly_crashed' = FALSE /\ \E h \in Node_SM!Compute_Checkpoint_Heights: Node_SM!Compute_Checkpoint(h) /\ UNCHANGED Subnet_vars /\ UNCHANGED needed_for_progress /\ UNCHANGED contributed /\ UNCHANGED can_obtain_stale_artifacts
    \/ freshly_crashed' = FALSE /\ \E h \in aux_manifest_heights: Node_SM!Compute_Manifest(h) /\ UNCHANGED Subnet_vars /\ UNCHANGED needed_for_progress /\ UNCHANGED contributed /\ UNCHANGED can_obtain_stale_artifacts
    \/ \E h \in Subnet_SM!Produce_CUP_Heights: \E s \in Subnet_SM!Produce_CUP_States(h): Conditionally_Produce_CUP(h, s)
    \/ \E h \in Subnet_SM!Produce_Block_Heights, p \in BLOCK_PAYLOADS: \E vc \in GENESIS_HEIGHT..h: Conditionally_Produce_Block(h, p, vc)
    \/ \E h \in Subnet_SM!Certify_State_Heights: \E s \in Subnet_SM!Certify_State_States(h): Conditionally_Certify_State(h, s)
    \/ \E h \in Accept_Block_Heights: Accept_Block(h)
    \/ \E h \in Accept_CUP_Heights: Accept_CUP(h)
    \/ \E h \in Accept_Certification_Heights: Accept_Certification(h)
    \/ \E h \in Sync_State_Heights, s \in STATES: Sync_State(h, cups[h])

Next ==
    \/ System_Actions
    \/ Environment_Actions

\******************************************************************************
\* Properties
\******************************************************************************

\*****************************
\* Sanity properties
\*****************************
\*
\* Used for model debugging; we expect them to be violated. If the model
\* doesn't violate them, there's something wrong with the model.

Sanity_No_Blocks == Subnet_SM!Sanity_No_Blocks
Sanity_No_Certifications == Subnet_SM!Sanity_No_Certifications
Sanity_No_Cups == Subnet_SM!Sanity_No_Cups
Sanity_Blocks_Cant_Reach_The_Max_Height == Subnet_SM!Sanity_Blocks_Cant_Reach_The_Max_Height
Sanity_Certifications_Cant_Reach_The_Max_Height == Subnet_SM!Sanity_Certifications_Cant_Reach_The_Max_Height
Sanity_Cups_Cant_Reach_The_Max_Height == Subnet_SM!Sanity_Cups_Cant_Reach_The_Max_Height
Inv_No_Holes_In_Blocks == Subnet_SM!Inv_No_Holes_In_Blocks
Inv_Certifications_Nonempty == Subnet_SM!Inv_Certifications_Nonempty
Inv_Cups_Nonempty == Subnet_SM!Inv_Cups_Nonempty
Sanity_Blocks_Cant_Reach_The_Max_Height_When_Needed_For_Progress == 
    <>[](needed_for_progress) => Sanity_Blocks_Cant_Reach_The_Max_Height
Sanity_Certifications_Cant_Reach_The_Max_Height_When_Needed_For_Progress == 
    <>[](needed_for_progress) => 
    Subnet_SM!Sanity_Certifications_Cant_Reach_The_Max_Height
Sanity_Cups_Cant_Reach_The_Max_Height_When_Needed_For_Progress == 
    <>[](needed_for_progress) => 
    Subnet_SM!Sanity_Cups_Cant_Reach_The_Max_Height

\*****************************
\* Actual properties: safety
\*****************************

\* Preliminaries

\* When checking safety, we can use symmetry reductions
Optimization_Symmetry ==
    Permutations(BLOCK_PAYLOADS) \union Permutations(STATES)

\* Additionally, for larger models (e.g., 8 heights), we need further,
\* potentially unsound optimizations. We introduce an equivalence relation on
\* states, and use it to reduce the state space.
\*
\* In particular, we ignore all subnet artifacts that are older than the last
\* certified checkpoint that the replica has.
\*
\* TODO (MR-514): it'd be great to check the soundness of this optimization. We should be
\*       able to do so using Apalache, by checking bidirectional refinement
\*       between the optimized version and the non-optimized version.
View ==
    LET
        max_ccp == Max(DOMAIN Node_SM!Certified_Checkpoints)
    IN 
    << Restrict(blocks, max_ccp..MAX_HEIGHT),
    Restrict(certifications, max_ccp..MAX_HEIGHT),
    Restrict(cups, max_ccp..MAX_HEIGHT),
    \* Local node variables (inherited from Abstract_Node_SM)
    states,
    Restrict(checkpoints, max_ccp..MAX_HEIGHT),
    manifests,
    {c \in local_certifications: c >= max_ccp},
    Restrict(local_cups, max_ccp..MAX_HEIGHT),
    Restrict(local_blocks, max_ccp..MAX_HEIGHT),
    \* Controls whether the replica is needed for progress
    needed_for_progress,
    \* Records which CUPs the replica has contributed to
    contributed,
    can_obtain_stale_artifacts >>

\* Properties

\* We check that the guard optimizations we introduce are correct.
Optimization_Correctness == 
    /\ Node_SM!Optimization_Correctness
    /\ Subnet_SM!Optimization_Correctness

\* The "certified tip" doesn't decrease.
Monotonic_Certified_Tip == 
    [][
        \/ Node_SM!Certified_Tip <= Node_SM!Certified_Tip'
    ]_vars

Keep_Producing_Cups == Subnet_SM!Keep_Producing_Cups
Keep_Producing_Blocks == Subnet_SM!Keep_Producing_Blocks
Keep_Certifying_States == Subnet_SM!Keep_Certifying_States

\* This will only hold until we introduce divergence.
No_State_Divergence == \A s \in STATES, h \in HEIGHTS:
    [](h \in DOMAIN states /\ states[h] = s => 
        [](h \notin DOMAIN states \/ states[h] = s)
    )

\* The main safety property. If the replica contributes to a CUP, it will
\* keep the corresponding checkpoint around, unless there's a CUP for a 
\* higher height around.
Replica_Keeps_CUP ==
    /\ [][\A h \in DOMAIN contributed: h \in DOMAIN contributed' /\ contributed'[h] = contributed[h]]_vars
    /\ [](\A h \in DOMAIN contributed:
            \/ h \in DOMAIN checkpoints /\ checkpoints[h] = contributed[h]
            \/ \E h2 \in h+1..MAX_HEIGHT: h2 \in DOMAIN cups
        )

\* Determine whether the first sequences is smaller than the second by lexicographic order (used for the variant)
Lex_Less(seq1, seq2) ==
    /\ Assert(Len(seq1) = Len(seq2), "Lex_Less: sequences have different lengths")
    /\ 
      LET
        diffs == {i \in 1..Len(seq1): seq1[i] # seq2[i]}
      IN
        /\ diffs # {}
        /\ seq1[Min(diffs)] < seq2[Min(diffs)]

\* Since we want to use equivalences on states, such as symmetry reductions and views, we can't directly rely on TLC checking our non-safety properties,
\* as TLC's algorithm isn't sound for non-safety properties under equivalences on states.
\* That is, we can't just state liveness properties using standard temporal operators such as "eventually".
\* Instead, we'll use the standard termination proving technique, variants, to show that the system eventually reaches
\* a desired state. A variant is something that decreases in each step, but cannot decrease forever.
\* (this is an "action invariant", over two succesive states, and can still be soundly checked by TLC).
\* We'll use a lexicographic ordering over the following sequence.
\* Once the sequence bottoms out, the system has achieved its liveness property.
Variant ==
    << 
        MAX_HEIGHT - Max(DOMAIN cups), 
        MAX_HEIGHT - Max(DOMAIN blocks \union {GENESIS_HEIGHT}), 
        MAX_HEIGHT - Max(DOMAIN local_cups),
        MAX_HEIGHT - Max(DOMAIN checkpoints),
        MAX_HEIGHT - Max(DOMAIN local_blocks \union {GENESIS_HEIGHT}),
        MAX_HEIGHT - Max(DOMAIN states),
        MAX_HEIGHT - Max(DOMAIN certifications),
        MAX_HEIGHT - Max(local_certifications),
        MAX_HEIGHT - Cardinality(DOMAIN manifests),
        MAX_HEIGHT - Cardinality(DOMAIN certifications),
        MAX_HEIGHT - Cardinality(local_certifications)
    >>

\* The action invariant statin that out variant always decreases.
\* But it comes with a twist: the variant doesn't need to decrease in an environment step,
\* such as crashing the node or toggling the needed_for_progress flag. This means that
\* we expect the system to terminate only if the environment steps don't happen infinitely
\* often. But this is reasonable, as we can't expect the replica to make progress if it
\* keeps crashing (at least, if the crashes are sufficiently frequent - but modeling frequency 
\* would be a pain, so just state that it doesn't crash infinitely often).
Variant_Decreasing ==
    [][
        /\ ~freshly_crashed'
        /\ ~Toggle_Needed_For_Progress 
        /\ ~Toggle_Stale_Artifact_Availability 
      => 
        Lex_Less(Variant', Variant)
    ]_vars 


\* Additionally, unlike traditional termination proofs, we also need to prove that the system
\* doesn't deadlock. We do this by asserting that system can either always take a step - and more
\* precisely, a step that's not an "environment" step like a crash, that doesn't decrease the 
\* variant - or the variant bottoms out. It's on you, dear reader, to ensure that once the
\* variant bottoms out we actually have the desired liveness property.
No_Deadlock ==
  LET
    MAX_CUP == Max({h \in GENESIS_HEIGHT..MAX_HEIGHT: IS_CHECKPOINT_HEIGHT(h)})
    VARIANT_DONE == << 
        MAX_HEIGHT - MAX_CUP, \* We've produced the last CUP
        0, \* We've produced the last block
        MAX_HEIGHT - MAX_CUP, \* The replica has the last CUP
        MAX_HEIGHT - MAX_CUP, \* The replica's produced the last checkpoint
        0, \* The replica has the last block
        0, \* The replica has the last state
        0, \* We've produced the last certification
        0, \* The replica has the last certification locally
        MAX_HEIGHT, \* The last few elements don't affect our liveness property
        MAX_HEIGHT,
        MAX_HEIGHT
     >>
  IN
    \/ Lex_Less(Variant, VARIANT_DONE)
    \/ ENABLED System_Actions

\*****************************
\* Actual properties: liveness
\*****************************
\*
\* Liveness is quite expensive to check directly, as we can't apply any optimizations.
\* But if you want to check it directly, use the following fairness conditions.

Conditional_Subnet_Fairness ==
    /\ WF_vars(
        \/ \E h \in Subnet_SM!Certify_State_Heights: \E s \in Subnet_SM!Certify_State_States(h): Conditionally_Certify_State(h, s)
        \/ \E h \in Subnet_SM!Produce_Block_Heights, p \in BLOCK_PAYLOADS, v \in HEIGHTS: Conditionally_Produce_Block(h, p, v)
        \/ \E h \in Subnet_SM!Produce_CUP_Heights: \E s \in Subnet_SM!Produce_CUP_States(h): Conditionally_Produce_CUP(h, s)
     )

Combined_Fairness ==
    /\ WF_vars(\E h \in HEIGHTS:
        \/ Accept_Block(h)
        \/ Accept_CUP(h)
        \/ Accept_Certification(h)
        \/ \E s \in STATES: Sync_State(h, s)
     )

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ 
        /\ []<><<
            /\ needed_for_progress = needed_for_progress'
            /\ can_obtain_stale_artifacts = can_obtain_stale_artifacts'
            /\ vars' # vars
         >>_vars
        /\ <>[][~Node_SM!Crash_And_Restart]_vars

====