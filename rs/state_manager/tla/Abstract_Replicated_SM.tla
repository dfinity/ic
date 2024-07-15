This is the abstract *replicated* state machine, that is, the state machine at the level of the entire subnet.
It describes only subnet-level artifacts: finalized blocks, certifications, and catchup packages (CUPs).

---- MODULE Abstract_Replicated_SM ----
EXTENDS TLC, Naturals, FiniteSets, FiniteSetsExt, Sequences, SequencesExt, Common_Defs, Util

VARIABLE 
    \* Finalized consensus blocks
    blocks,
    \* Certifications for in-memory states
    certifications,
    \* Catchup packages (CUPs)
    cups,
    \* Auxiliary variables used to speed up guard evaluation.
    aux_next_block_height,
    aux_next_cup_height,
    aux_possible_certifications

vars == << blocks, certifications, cups, exec_f  >>

\* Subnet-level artifacts may get garbage collected. This could make them
\* unavailable to the replica. But removing such artifacts from the state would
\* complicate the model significantly (e.g., computation of CUPs and
\* certifications if blocks are only partially available). Instead we store all
\* the historic artifacts in the state, and use the following predicates to
\* distinguish those that we know are not garbage collected.
\* Note that when an artifact is not *guaranteed* to be available, it doesn't mean
\* it's *not* available. For example, an attacker could selectively make artifacts available to try
\* and steer a node into a bad state or inhibit liveness in a different way.
Guaranteed_Available_Blocks == Restrict(blocks, Max(DOMAIN cups)..MAX_HEIGHT)
Guaranteed_Available_CUPs == Restrict(cups, {Max(DOMAIN(cups))})
Guaranteed_Available_Certifications == Restrict(certifications, Max(DOMAIN cups)..MAX_HEIGHT)

\* We express some of the action guards in two variants: a "simple" guard which captures the meaning, and the actually
\* used guard that uses some pre-computed information to speed up TLC. The equality of the two guards
\* is asserted in the Optimization_Correctness property.
Produce_Block_Heights_Simple == {Max(DOMAIN blocks \union {GENESIS_HEIGHT}) + 1} \intersect HEIGHTS
Produce_Block_Heights == aux_next_block_height

\* Action: extend the chain with a new block (i.e., models a block finalization)
Produce_Block(height, payload, validation_context) ==
    /\ height \in Produce_Block_Heights
    \* Our consensus assumes that a CUP occurs in every checkpoint interval.
    /\ height - Max(DOMAIN cups) 
        < 2 * CHECKPOINT_INTERVAL
    /\
      LET
        lower_vc_bound == IF height - 1 \in DOMAIN blocks
            THEN blocks[height - 1].validation_context
            ELSE GENESIS_HEIGHT
        upper_vc_bound == Max(DOMAIN certifications)
      IN validation_context \in lower_vc_bound..upper_vc_bound
    \* In order to produce a CUP, the validation context has to move past the height of the
    \* summary block. Hence, consensus indirectly assumes that there is enough synchrony so
    \* that the validation context moves past the height of the summary block within the checkpoint 
    \* interval.
    \* We have to make that assumption explicit here, otherwise the model could deadlock.
    /\ IS_CHECKPOINT_HEIGHT(height + 1) => validation_context >= Previous_Checkpoint_Height(height)
    /\ blocks' = height :> [ 
            validation_context |-> validation_context, 
            payload |-> payload 
        ] 
        @@ blocks
    /\ aux_next_block_height' = IF height = MAX_HEIGHT THEN {} ELSE {height + 1}
    /\ aux_next_cup_height' = IF IS_CHECKPOINT_HEIGHT(height) THEN {height} ELSE aux_next_cup_height
    /\ aux_possible_certifications' = aux_possible_certifications \union {height}
    /\ UNCHANGED << certifications, cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED genesis_state

\* We express some of the action guards in two variants: a "simple" guard which captures the meaning, and the actually
\* used guard that uses some pre-computed information to speed up TLC. The equality of the two guards
\* is asserted in the Optimization_Correctness property.
Certify_State_Heights_Simple == DOMAIN blocks \ DOMAIN certifications
Certify_State_Heights == aux_possible_certifications

Certify_State_States(height) == {
    FoldLeft(Execute_Block, genesis_state, [i \in GENESIS_HEIGHT+1..height |-> blocks[i].payload])}

\* Action: certify a state
Certify_State(height, state) ==
    /\ height \in Certify_State_Heights
    /\ state \in Certify_State_States(height)
    /\ certifications' = height :> state @@ certifications
    /\ aux_possible_certifications' = aux_possible_certifications \ {height}
    /\ UNCHANGED << blocks, cups >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_next_block_height
    /\ UNCHANGED aux_next_cup_height
    /\ UNCHANGED genesis_state

\* We express some of the action guards in two variants: a "simple" guard which captures the meaning, and the actually
\* used guard that uses some pre-computed information to speed up TLC. The equality of the two guards
\* is asserted in the Optimization_Correctness property.
Produce_CUP_Heights_Simple == {Max(DOMAIN cups) + CHECKPOINT_INTERVAL} \intersect DOMAIN blocks
Produce_CUP_Heights == aux_next_cup_height
Produce_CUP_States(height) == {FoldLeft(Execute_Block, genesis_state, [i \in GENESIS_HEIGHT+1..height |-> blocks[i].payload])}

\* Action: produce a CUP
Produce_CUP(height, state) ==
    /\ height \in Produce_CUP_Heights
    /\ state \in Produce_CUP_States(height)
    \* Replicas won't issue CUP shares until they obtain a block
    \* whose validation context is at least the height of the summary block.
    /\ \E hb \in DOMAIN blocks: 
        /\ hb > height
        /\ blocks[hb].validation_context >= height
    /\ cups' = height :> state @@ cups
    /\ aux_next_cup_height' = {}
    \* /\ aux_possible_certifications' = aux_possible_certifications \ GENESIS_HEIGHT..height-1
    /\ UNCHANGED << blocks, certifications >>
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_next_block_height
    /\ UNCHANGED aux_possible_certifications
    /\ UNCHANGED genesis_state

\* Since we can only analyze a finite number of blocks, the model will deadlock
\* once we have produced everything up to MAX_HEIGHT. Add an idle action to 
\* prevent TLC about complaining about deadlock, while still keeping deadlock
\* checking on for other cases.
Idle ==
    /\ DOMAIN cups = {i \in GENESIS_HEIGHT..MAX_HEIGHT: IS_CHECKPOINT_HEIGHT(i)}
    /\ DOMAIN blocks = GENESIS_HEIGHT+1..MAX_HEIGHT
    /\ DOMAIN certifications = GENESIS_HEIGHT..MAX_HEIGHT
    /\ UNCHANGED vars
    /\ UNCHANGED exec_f
    /\ UNCHANGED aux_next_block_height
    /\ UNCHANGED aux_next_cup_height
    /\ UNCHANGED aux_possible_certifications

Init ==
    /\ genesis_state \in STATES
    /\ blocks = [ x \in {} |-> {} ]
    /\ certifications = GENESIS_HEIGHT :> genesis_state
    /\ cups = GENESIS_HEIGHT :> genesis_state
    /\ Init_Common
    /\ aux_next_block_height = IF MAX_HEIGHT > GENESIS_HEIGHT THEN {GENESIS_HEIGHT + 1} ELSE {}
    /\ aux_next_cup_height = {}
    /\ aux_possible_certifications = {}

Next ==
    \/ \E h \in Produce_Block_Heights, p \in BLOCK_PAYLOADS: \E vc \in GENESIS_HEIGHT..h: Produce_Block(h, p, vc)
    \/ \E h \in Produce_CUP_Heights: \E s \in Produce_CUP_States(h): Produce_CUP(h, s)
    \/ \E h \in Certify_State_Heights: \E s \in Certify_State_States(h): Certify_State(h, s)
    \/ Idle

\*********************************************************
\* Sanity check properties
\*********************************************************

\* These properties should not hold. If they do hold, the model is bogus as
\* it's omitting expected behaviors. 
\* I.e., these properties are used during the development only, as a 
\* model validation/debugging aid.

Sanity_No_Blocks ==
    DOMAIN blocks = {}

Sanity_No_Certifications ==
    DOMAIN certifications = {GENESIS_HEIGHT}

Sanity_No_Cups ==
    DOMAIN cups = {GENESIS_HEIGHT}

Sanity_Blocks_Cant_Reach_The_Max_Height ==
    \/ DOMAIN blocks = {} 
    \/ Max(DOMAIN blocks) # Max(HEIGHTS)

Sanity_Certifications_Cant_Reach_The_Max_Height ==
    Max(DOMAIN certifications) # Max(HEIGHTS)

Sanity_Cups_Cant_Reach_The_Max_Height ==
    Max(DOMAIN cups) # Max({ h \in HEIGHTS: IS_CHECKPOINT_HEIGHT(h) })

\*********************************************************
\* Properties
\*********************************************************

\* The model should produce blocks in succession, without gaps.
Inv_No_Holes_In_Blocks ==
    \A h \in HEIGHTS: h \in DOMAIN blocks => h - 1 \in (DOMAIN blocks \union {GENESIS_HEIGHT})
\* In the model, we should always have at least the genesis state certified.
Inv_Certifications_Nonempty == DOMAIN certifications # {}
\* Similarly, we should always have at least the genesis state in the CUPs.
Inv_Cups_Nonempty == DOMAIN cups # {}

\* The liveness properties are as usual conditioned on a fairness property.
Fairness ==
    /\ \A h \in HEIGHTS:
        /\ \A p \in BLOCK_PAYLOADS, vc \in HEIGHTS:
            /\ WF_vars(Produce_Block(h, p, vc))
        /\ \A s \in STATES:
            /\ WF_vars(Produce_CUP(h, s))
            /\ WF_vars(Certify_State(h, s))

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ Fairness

\* Property: we can always get a CUP for every state
Keep_Producing_Cups ==
    \* We can't produce a CUP for the last height,
    \* as we need the validation context to move past 
    \* the CUP height
    \A h \in HEIGHTS \ {Max(HEIGHTS)}: 
        IS_CHECKPOINT_HEIGHT(h) => <>(h \in DOMAIN cups)

Keep_Producing_Blocks ==
    \A h \in HEIGHTS \ {GENESIS_HEIGHT}: 
        <>(h \in DOMAIN blocks)

Keep_Certifying_States ==
    \* We only ask for the certification of the last height,
    \* since we might not certify some states if they get garbage collected.
    \* I.e., the following version doesn't hold:
    \* \A h \in HEIGHTS \ {GENESIS_HEIGHT}: 
    \*    <>(h \in DOMAIN certifications)
    \* But certifying the last height should indirectly certify all the other
    \* states, since the states contain the hash of their predecessor state.
    <>(MAX_HEIGHT \in DOMAIN certifications)

Optimization_Correctness == 
    /\ Produce_Block_Heights = Produce_Block_Heights_Simple
    /\ Certify_State_Heights = Certify_State_Heights_Simple
    /\ Produce_CUP_Heights = Produce_CUP_Heights_Simple

====