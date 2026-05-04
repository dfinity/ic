---- MODULE StateManager -------------------------------------------------------
(* This module is a specification of the StateManager component. *)

EXTENDS Naturals

CONSTANT States       \* The state type is abstract.
CONSTANT InitialState \* Since the initial state initial state is an argument.

VARIABLE states

ASSUME InitialState \in States

(* The invariant for the StateManager state variables. *)
TypeInvariant == states \in [
  snapshots : [Nat -> States], \* Maps heights to in-memory states.
  manifests : SUBSET Nat       \* The set of states for which we computed manifests.
]

Init == states = [ snapshots |-> InitialState, manifests |-> {} ]

Next == UNCHANGED states

Spec == Init /\ [][Next]_states

================================================================================

