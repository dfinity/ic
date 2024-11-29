---- MODULE Spawn_Neurons ----
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

\* IDs for processes. We'll use one process per governance call, to be able to control how many of each call we analyze.
\* As we model ledger operations as atomic, we'll have just one ledger process.
CONSTANTS
    \* @type: Set($proc);
    Spawn_Neurons_Process_Ids,
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

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
transfer(from, to, amount, fee) == Variant("Transfer", [from |-> from, to |-> to, amount |-> amount, fee |-> fee])

(*--algorithm Governance_Ledger_Spawn_Neurons {

\* The neuron state kept by the governance canister. We're recording this as a global variable, and not a process
\* since we use processes to model method calls on the governance canister
variables
    neuron \in [{} -> {}];
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account \in [{} -> {}];
    \* The set of currently locked neurons
    locks = {};
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger = <<>>;
    ledger_to_governance = {};
    spawning_neurons = TRUE;

\* The Rust code of spawn_neurons (called in the timer) uses a for loop with an await inside.
\* This is awkward to model in PlusCal while preserving the 1-1 mapping of TLA transitions
\* to code message handlers (a while loop would require some extra labels).
\* A 1-1 mapping, as far as I can tell, requires some code duplication.
\* We extract the duplicated part into a macro, and place the labels appropriately.
\* In some cases we'll want to update the locks twice in the same message handler. To work around
\* PlusCal not being able to do that, we'll pass the new value of locks as a parameter to the macro.
macro loop_iteration(new_locks) {
        with(nid \in ready_to_spawn_neuron_ids \ locks;
            \* TODO: the maturity modulation stuff stuff is here
            neuron_stake = neuron[nid].maturity;
            account = neuron[nid].account;
        ) {
            neuron_id := nid;
            locks := new_locks \union {neuron_id};
            neuron := [ neuron EXCEPT
                        ![neuron_id].maturity = 0,
                        ![neuron_id].cached_stake = neuron_stake
                      ];
            governance_to_ledger := Append(governance_to_ledger,
                request(self, transfer(Minting_Account_Id, account, neuron_stake, 0)));
            goto SpawnNeurons_WaitForTransfer;
        };
}

process (Spawn_Neurons \in Spawn_Neurons_Process_Ids)
    variables
        neuron_id = 0;
        ready_to_spawn_neuron_ids = {};
    {

    SpawnNeurons_Start:
        \* TODO: do we need to model the maturity modulation madness?

        await ~spawning_neurons;

        \* TODO: probably need to model the spawning state
        ready_to_spawn_neuron_ids := {nid \in DOMAIN(neuron) : neuron[nid].maturity > 0};
        await ready_to_spawn_neuron_ids # {};
        spawning_neurons := TRUE;
        loop_iteration(locks);
    SpawnNeurons_WaitForTransfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self };
            \* Work around PlusCal not being able to assing to the same variable twice in the same block
            new_locks = IF answer.response # Variant("Fail", UNIT)
                THEN locks \ {neuron_id}
                ELSE locks;
        ) {
            ledger_to_governance := ledger_to_governance \ {answer};

            ready_to_spawn_neuron_ids := ready_to_spawn_neuron_ids \ {neuron_id};
            if(ready_to_spawn_neuron_ids = {}) {
                spawning_neurons := FALSE;
                locks := new_locks;
                neuron_id := 0;
                goto SpawnNeurons_Start;
            } else {
                loop_iteration(new_locks);
            };
        };
    }

}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "c640a12" /\ chksum(tla) = "2d61236c")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, spawning_neurons, neuron_id,
          ready_to_spawn_neuron_ids

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, spawning_neurons, neuron_id,
           ready_to_spawn_neuron_ids >>

ProcSet == (Spawn_Neurons_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = TRUE
        (* Process Spawn_Neurons *)
        /\ neuron_id = [self \in Spawn_Neurons_Process_Ids |-> 0]
        /\ ready_to_spawn_neuron_ids = [self \in Spawn_Neurons_Process_Ids |-> {}]
        /\ pc = [self \in ProcSet |-> "SpawnNeurons_Start"]

SpawnNeurons_Start(self) == /\ pc[self] = "SpawnNeurons_Start"
                            /\ ~spawning_neurons
                            /\ ready_to_spawn_neuron_ids' = [ready_to_spawn_neuron_ids EXCEPT ![self] = {nid \in DOMAIN(neuron) : neuron[nid].maturity > 0}]
                            /\ ready_to_spawn_neuron_ids'[self] # {}
                            /\ spawning_neurons' = TRUE
                            /\ \E nid \in ready_to_spawn_neuron_ids'[self] \ locks:
                                 LET neuron_stake == neuron[nid].maturity IN
                                   LET account == neuron[nid].account IN
                                     /\ neuron_id' = [neuron_id EXCEPT ![self] = nid]
                                     /\ locks' = (locks \union {neuron_id'[self]})
                                     /\ neuron' = [ neuron EXCEPT
                                                    ![neuron_id'[self]].maturity = 0,
                                                    ![neuron_id'[self]].cached_stake = neuron_stake
                                                  ]
                                     /\ governance_to_ledger' =                     Append(governance_to_ledger,
                                                                request(self, transfer(Minting_Account_Id, account, neuron_stake, 0)))
                                     /\ pc' = [pc EXCEPT ![self] = "SpawnNeurons_WaitForTransfer"]
                            /\ UNCHANGED << neuron_id_by_account,
                                            ledger_to_governance >>

SpawnNeurons_WaitForTransfer(self) == /\ pc[self] = "SpawnNeurons_WaitForTransfer"
                                      /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self }:
                                           LET new_locks ==         IF answer.response # Variant("Fail", UNIT)
                                                            THEN locks \ {neuron_id[self]}
                                                            ELSE locks IN
                                             /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                             /\ ready_to_spawn_neuron_ids' = [ready_to_spawn_neuron_ids EXCEPT ![self] = ready_to_spawn_neuron_ids[self] \ {neuron_id[self]}]
                                             /\ IF ready_to_spawn_neuron_ids'[self] = {}
                                                   THEN /\ spawning_neurons' = FALSE
                                                        /\ locks' = new_locks
                                                        /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                                                        /\ pc' = [pc EXCEPT ![self] = "SpawnNeurons_Start"]
                                                        /\ UNCHANGED << neuron,
                                                                        governance_to_ledger >>
                                                   ELSE /\ \E nid \in ready_to_spawn_neuron_ids'[self] \ locks:
                                                             LET neuron_stake == neuron[nid].maturity IN
                                                               LET account == neuron[nid].account IN
                                                                 /\ neuron_id' = [neuron_id EXCEPT ![self] = nid]
                                                                 /\ locks' = (new_locks \union {neuron_id'[self]})
                                                                 /\ neuron' = [ neuron EXCEPT
                                                                                ![neuron_id'[self]].maturity = 0,
                                                                                ![neuron_id'[self]].cached_stake = neuron_stake
                                                                              ]
                                                                 /\ governance_to_ledger' =                     Append(governance_to_ledger,
                                                                                            request(self, transfer(Minting_Account_Id, account, neuron_stake, 0)))
                                                                 /\ pc' = [pc EXCEPT ![self] = "SpawnNeurons_WaitForTransfer"]
                                                        /\ UNCHANGED spawning_neurons
                                      /\ UNCHANGED neuron_id_by_account

Spawn_Neurons(self) == SpawnNeurons_Start(self)
                          \/ SpawnNeurons_WaitForTransfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Spawn_Neurons_Process_Ids: Spawn_Neurons(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION
====
