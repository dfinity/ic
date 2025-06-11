---- MODULE Disburse_Maturity ----
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants, Common

CONSTANTS
    \* @type: Set($proc);
    Disburse_Maturity_Process_Ids,
    \* @type: $account;
    Minting_Account_Id,
    \* @type: Set($account);
    Account_Ids

\* Constants from the actual code
CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE,
    \* TODO: check whether it makes sense to take the maturity modulation into account
    MIN_DISBURSEMENT

CONSTANT
    FRESH_NEURON_ID(_)

(* --algorithm Governance_Ledger_Disburse_Maturity {

variables
    neuron \in [{} -> {}];
    neuron_id_by_account \in [{} -> {}];
    locks = {};
    governance_to_ledger = <<>>;
    ledger_to_governance = {};
    spawning_neurons = FALSE;

\* Since disburse_maturity always executes in a single message handler, there's no real need
\* to support multiple procesees (i.e., we could've had `Disburse_Maturity = Disburse_Maturity_Process_Id`
\* here instead of choosing from the set of `Disburse_Maturity_Process_Ids`). But there's no significant
\* upside to that over using a singleton Disburse_Maturity_Process_Ids set, and the TLA-code link tooling
\* expects a process to take a `self` parameter, which is only the case if we use a set of process ids.
\* So we just do the easier thing here. Furthermore, having a set of process IDs allows us to use an 
\* empty set during model checking, allowing us to check only a subset of the processes in case we start
\* exhausting resources while model checking.
process (Disburse_Maturity \in Disburse_Maturity_Process_Ids)
    {
        DisburseMaturityStart:
        while(TRUE) {
            \* A few checks are skipped here.
            \* As these can fail in the implementation, and we are checking that the implementation is aligned
            \* with the model, the model also needs to "fail" the disburse operation due to these checks failing.
            \* We model this by non-deterministically making Disburse_Maturity into a no-op.
            either {
                skip;
            } or {
                with(neuron_id \in DOMAIN(neuron) \ locks;
                    account_id \in Account_Ids;
                    amount_to_disburse \in MIN_DISBURSEMENT..neuron[neuron_id].maturity;
                ) {
                    await(neuron[neuron_id].state # SPAWNING);

                    neuron := [ neuron EXCEPT ![neuron_id].maturity = @ - amount_to_disburse,
                        ![neuron_id].maturity_disbursements_in_progress = Append(@, [ account_id |-> account_id, amount |-> amount_to_disburse ])
                    ];
                };
            };
        }
    }

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "a946d019" /\ chksum(tla) = "dec91db8")
VARIABLES neuron, neuron_id_by_account, locks, governance_to_ledger, 
          ledger_to_governance, spawning_neurons

vars == << neuron, neuron_id_by_account, locks, governance_to_ledger, 
           ledger_to_governance, spawning_neurons >>

ProcSet == (Disburse_Maturity_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = FALSE

Disburse_Maturity(self) == /\ \/ /\ TRUE
                                 /\ UNCHANGED neuron
                              \/ /\ \E neuron_id \in DOMAIN(neuron) \ locks:
                                      \E account_id \in Account_Ids:
                                        \E amount_to_disburse \in MIN_DISBURSEMENT..neuron[neuron_id].maturity:
                                          /\ (neuron[neuron_id].state # SPAWNING)
                                          /\ neuron' =           [ neuron EXCEPT ![neuron_id].maturity = @ - amount_to_disburse,
                                                           ![neuron_id].maturity_disbursements_in_progress = Append(@, [ account_id |-> account_id, amount |-> amount_to_disburse ])
                                                       ]
                           /\ UNCHANGED << neuron_id_by_account, locks, 
                                           governance_to_ledger, 
                                           ledger_to_governance, 
                                           spawning_neurons >>

Next == (\E self \in Disburse_Maturity_Process_Ids: Disburse_Maturity(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

====
