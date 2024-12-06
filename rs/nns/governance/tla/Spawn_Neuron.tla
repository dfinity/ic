---- MODULE Spawn_Neuron ----
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

CONSTANTS
    \* @type: Set($proc);
    Spawn_Neuron_Process_Ids,
    \* @type: Set($account);
    Governance_Account_Ids,
    \* @type: $account;
    Minting_Account_Id

\* Constants from the actual code
CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE

CONSTANT
    FRESH_NEURON_ID(_)

(* --algorithm Governance_Ledger_Spawn_Neuron {

variables
    neuron \in [{} -> {}];
    neuron_id_by_account \in [{} -> {}];
    locks = {};
    governance_to_ledger = <<>>;
    ledger_to_governance = {};

\* Since spawn_neuron always executes in a single message handler, there's no real need
\* to support multiple procesees (i.e., we could've had `Spasn_Neuron = Spawn_Neuron_Process_Id`
\* here instead of choosing from the set of `Spawn_Neuron_Process_Ids`). But there's no significant
\* upside to that over using a singleton Spawn_Neuron_Process_Ids set, and the TLA-code link tooling
\* expects a process to take a `self` parameter, which is only the case if we use a set of process ids.
\* So we just do the easier thing here.
process (Spawn_Neuron \in Spawn_Neuron_Process_Ids)
    {
        SpawnNeuronStart:
        while(TRUE) {
            \* A few checks are skipped here:
            \* 1. that the heap can grow
            \* 2. that the caller controls the parent neuron
            \* 3. That the child controller is valid
            \* As these can fail in the implementation, and we are checking that the implementation is aligned
            \* with the model, the model also needs to "fail" the spawn operation due to these checks failing.
            \* We model this by non-deterministically making Spawn_Neuron into a no-op.
            either {
                skip;
            } or {
                with(parent_neuron_id \in DOMAIN(neuron) \ locks;
                    child_account_id \in Governance_Account_Ids \ DOMAIN neuron_id_by_account;
                    maturity_to_spawn \in MIN_STAKE..neuron[parent_neuron_id].maturity;
                    child_neuron_id = FRESH_NEURON_ID(DOMAIN(neuron));
                ) {

                    \* The code takes a lock on the child neuron, but releases it in the same message handler,
                    \* effectively only checking that the lock isn't already taken.
                    await child_neuron_id \notin locks;

                    neuron_id_by_account := child_account_id :> child_neuron_id @@ neuron_id_by_account;
                    neuron := child_neuron_id :> [ cached_stake |-> 0, account |-> child_account_id, fees |-> 0, maturity |-> maturity_to_spawn ]
                           @@ [ neuron EXCEPT ![parent_neuron_id].maturity = @ - maturity_to_spawn ];
                };
            };
        }
    }

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "8e28ba76" /\ chksum(tla) = "e2a72833")
VARIABLES neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance

vars == << neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance >>

ProcSet == (Spawn_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}

Spawn_Neuron(self) == /\ \/ /\ TRUE
                            /\ UNCHANGED <<neuron, neuron_id_by_account>>
                         \/ /\ \E parent_neuron_id \in DOMAIN(neuron) \ locks:
                                 \E child_account_id \in Governance_Account_Ids \ DOMAIN neuron_id_by_account:
                                   \E maturity_to_spawn \in MIN_STAKE..neuron[parent_neuron_id].maturity:
                                     LET child_neuron_id == FRESH_NEURON_ID(DOMAIN(neuron)) IN
                                       /\ child_neuron_id \notin locks
                                       /\ neuron_id_by_account' = (child_account_id :> child_neuron_id @@ neuron_id_by_account)
                                       /\ neuron' = (   child_neuron_id :> [ cached_stake |-> 0, account |-> child_account_id, fees |-> 0, maturity |-> maturity_to_spawn ]
                                                     @@ [ neuron EXCEPT ![parent_neuron_id].maturity = @ - maturity_to_spawn ])
                      /\ UNCHANGED << locks, governance_to_ledger,
                                      ledger_to_governance >>

Next == (\E self \in Spawn_Neuron_Process_Ids: Spawn_Neuron(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

====
