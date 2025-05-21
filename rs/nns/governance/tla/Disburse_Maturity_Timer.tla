---- MODULE Disburse_Maturity_Timer ----
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants, Common

CONSTANTS
    \* @type: Set($proc);
    Disburse_Maturity_Timer_Process_Ids,
    \* @type: $account;
    Minting_Account_Id

\* Constants from the actual code
CONSTANTS
    \* Minimum stake a neuron can have
    \* @type: Int;
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    \* @type: Int;
    TRANSACTION_FEE,
    \* @type: Int;
    MATURITY_BASIS_POINTS

BASIS_POINTS_PER_UNITY == 10000

DUMMY_DISBURSEMENT == [ account_id |-> DUMMY_ACCOUNT, amount |-> 0 ]

(*--algorithm Governance_Ledger_Disburse_Maturity_Timer {

variables
    neuron \in [{} -> {}];
    neuron_id_by_account \in [{} -> {}];
    locks = {};
    governance_to_ledger = <<>>;
    ledger_to_governance = {};

process (Disburse_Maturity_Timer \in Disburse_Maturity_Timer_Process_Ids)
    variables
        neuron_id = 0;
        current_disbursement = DUMMY_DISBURSEMENT;
    {
    Disburse_Maturity_Timer_Start:
        either {
            goto Disburse_Maturity_Timer_Start;
        } or {
            with(nid \in
                { nid \in DOMAIN(neuron) \ locks : neuron[nid].maturity_disbursements_in_progress # <<>> };
                disbursement = Head(neuron[nid].maturity_disbursements_in_progress);
                amount_to_disburse = (disbursement.amount * (BASIS_POINTS_PER_UNITY + MATURITY_BASIS_POINTS)) \div BASIS_POINTS_PER_UNITY
            ) {
                neuron_id := nid;
                neuron := [neuron EXCEPT ![neuron_id].maturity_disbursements_in_progress = Tail(@) ];
                locks := locks \union {neuron_id};
                current_disbursement := disbursement;
                governance_to_ledger := Append(governance_to_ledger,
                    request(self, transfer(Minting_Account_Id, disbursement.account_id, amount_to_disburse, 0)));
            }
        };
    Disburse_Maturity_Timer_WaitForTransfer:
        with(answer \in { resp \in ledger_to_governance: resp.caller = self };
            \* Work around PlusCal not being able to assing to the same variable twice in the same block
        ) {
            ledger_to_governance := ledger_to_governance \ {answer};

            if(answer.response = Variant("Fail", UNIT)) {
                either {
                    neuron := [neuron EXCEPT ![neuron_id].maturity_disbursements_in_progress = << current_disbursement >> \o @ ];
                    locks := locks \ {neuron_id};
                } or {
                    skip
                }
            } else {
                locks := locks \ {neuron_id};
            }
        };
        current_disbursement := DUMMY_DISBURSEMENT;
        neuron_id := 0;
        goto Disburse_Maturity_Timer_Start;
    }
}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "1bdda2ab" /\ chksum(tla) = "f4d6f297")
VARIABLES pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
          ledger_to_governance, neuron_id, current_disbursement

vars == << pc, neuron, neuron_id_by_account, locks, governance_to_ledger,
           ledger_to_governance, neuron_id, current_disbursement >>

ProcSet == (Disburse_Maturity_Timer_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        (* Process Disburse_Maturity_Timer *)
        /\ neuron_id = [self \in Disburse_Maturity_Timer_Process_Ids |-> 0]
        /\ current_disbursement = [self \in Disburse_Maturity_Timer_Process_Ids |-> DUMMY_DISBURSEMENT]
        /\ pc = [self \in ProcSet |-> "Disburse_Maturity_Timer_Start"]

Disburse_Maturity_Timer_Start(self) == /\ pc[self] = "Disburse_Maturity_Timer_Start"
                                       /\ \/ /\ pc' = [pc EXCEPT ![self] = "Disburse_Maturity_Timer_Start"]
                                             /\ UNCHANGED <<neuron, locks, governance_to_ledger, neuron_id, current_disbursement>>
                                          \/ /\ \E nid \in { nid \in DOMAIN(neuron) \ locks : neuron[nid].maturity_disbursements_in_progress # <<>> }:
                                                  LET disbursement == Head(neuron[nid].maturity_disbursements_in_progress) IN
                                                    LET amount_to_disburse == (disbursement.amount * (BASIS_POINTS_PER_UNITY + MATURITY_BASIS_POINTS)) \div BASIS_POINTS_PER_UNITY IN
                                                      /\ neuron_id' = [neuron_id EXCEPT ![self] = nid]
                                                      /\ neuron' = [neuron EXCEPT ![neuron_id'[self]].maturity_disbursements_in_progress = Tail(@) ]
                                                      /\ locks' = (locks \union {neuron_id'[self]})
                                                      /\ current_disbursement' = [current_disbursement EXCEPT ![self] = disbursement]
                                                      /\ governance_to_ledger' =                     Append(governance_to_ledger,
                                                                                 request(self, transfer(Minting_Account_Id, disbursement.account_id, amount_to_disburse, 0)))
                                             /\ pc' = [pc EXCEPT ![self] = "Disburse_Maturity_Timer_WaitForTransfer"]
                                       /\ UNCHANGED << neuron_id_by_account,
                                                       ledger_to_governance >>

Disburse_Maturity_Timer_WaitForTransfer(self) == /\ pc[self] = "Disburse_Maturity_Timer_WaitForTransfer"
                                                 /\ \E answer \in { resp \in ledger_to_governance: resp.caller = self }:
                                                      /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                                      /\ IF answer.response = Variant("Fail", UNIT)
                                                            THEN /\ \/ /\ neuron' = [neuron EXCEPT ![neuron_id[self]].maturity_disbursements_in_progress = << current_disbursement[self] >> \o @ ]
                                                                       /\ locks' = locks \ {neuron_id[self]}
                                                                    \/ /\ TRUE
                                                                       /\ UNCHANGED <<neuron, locks>>
                                                            ELSE /\ locks' = locks \ {neuron_id[self]}
                                                                 /\ UNCHANGED neuron
                                                 /\ current_disbursement' = [current_disbursement EXCEPT ![self] = DUMMY_DISBURSEMENT]
                                                 /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                                                 /\ pc' = [pc EXCEPT ![self] = "Disburse_Maturity_Timer_Start"]
                                                 /\ UNCHANGED << neuron_id_by_account,
                                                                 governance_to_ledger >>

Disburse_Maturity_Timer(self) == Disburse_Maturity_Timer_Start(self)
                                    \/ Disburse_Maturity_Timer_WaitForTransfer(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Disburse_Maturity_Timer_Process_Ids: Disburse_Maturity_Timer(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION
====
