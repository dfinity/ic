---- MODULE DSM ----------------------------------------------------------------

EXTENDS Naturals, TLC

CONSTANTS Blocks (* The set of all blocks *)
        , States (* The set of all states *)
        , InitialState (* The initial state drawn from States *)

VARIABLES blockOffset (* See Consensus!blockOffset *)
        , blockChain  (* See Consensus!blockChain *)
        , processingState (* The height of the state DSM processes. *)
        , dsmStates (* The map from state heights to states *)
        , dsmStatus

ASSUME InitialState \in States

C == INSTANCE Consensus

Max(S) == CHOOSE x \in S : \A y \in S : x >= y

ready == "ready"
ticking == "ticking"

LOCAL dsmVars == <<processingState, dsmStates, dsmStatus>>

TypeOk ==
    /\ C!TypeOk
    /\ processingState \in Nat
    /\ DOMAIN dsmStates # {}
    \*/\ dsmStates \in [Nat -> States]
    /\ dsmStatus \in { ready, ticking }

lastStateIndex == Max(DOMAIN dsmStates)

Init ==
    /\ C!Init
    /\ dsmStatus = ready
    /\ processingState = 0
    /\ dsmStates = 0 :> InitialState

(* Process the next block in the chain. *)
AcceptBlock ==
    /\ dsmStatus = ready
    /\ lastStateIndex >= blockOffset
    /\ lastStateIndex < C!lastBlockIndex
    /\ dsmStatus' = ticking
    /\ processingState' = lastStateIndex + 1
    /\ UNCHANGED <<blockOffset, blockChain, dsmStates>>

(* Complete the block processing and publish the newly computed state. *)
Tick ==
    /\ dsmStatus = ticking
    /\ \E s \in States : dsmStates' = processingState :> s @@ dsmStates
    /\ dsmStatus = ready
    /\ UNCHANGED <<blockOffset, blockChain, processingState>>

Next ==
    \/ C!Next /\ UNCHANGED dsmVars
    \/ AcceptBlock
    \/ Tick

ModelSizeConstraint == C!SmallChainConstraint

================================================================================
