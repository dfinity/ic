------------ MODULE Claim_Neuron ------------
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

CONSTANT
    FRESH_NEURON_ID(_)

CONSTANTS 
    Governance_Account_Ids, 
    Neuron_Ids

CONSTANTS 
    Claim_Neuron_Process_Ids

CONSTANTS 
    \* Minimum stake a neuron can have
    MIN_STAKE,
    \* The transfer fee charged by the ledger canister
    TRANSACTION_FEE

OP_ACCOUNT_BALANCE == "account_balance"
ACCOUNT_BALANCE_FAIL == "Err"
DUMMY_ACCOUNT == ""

\* @type: (a -> b, Set(a)) => a -> b;
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x]]

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
account_balance(account) == Variant("AccountBalance", [account |-> account])


(* --algorithm Governance_Ledger_Claim_Neuron {

variables 
    
    neuron \in [{} -> {}];
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account \in [{} -> {}];
    \* The set of currently locked neurons
    locks = {};
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger = <<>>;
    ledger_to_governance = {};

macro cn_reset_local_vars() {
    account := DUMMY_ACCOUNT;
    neuron_id := 0;
}


\* Copied directly from formal-models/tla/governance-ledger
\* A Claim_Neuron process simulates a call to claim_neuron
process ( Claim_Neuron \in Claim_Neuron_Process_Ids )
    variable
        \* The account is an argument to the canister call; we let it be chosen non-deteministically
        account = DUMMY_ACCOUNT;
        \* The neuron_id will be set later on to a fresh value
        neuron_id = 0;
    { 
    ClaimNeuron1:
        either {
            \* Simulate calls that just fail early and don't change the state.
            \* Not so useful for model checking, but needed to follow the code traces.
            goto Done;
        } or {
        with(aid \in  Governance_Account_Ids \ DOMAIN(neuron_id_by_account)) {
            account := aid;
            \* Get a fresh neuron ID
            neuron_id := FRESH_NEURON_ID(DOMAIN(neuron));
            \* The Rust code tries to obtain a lock; this should always succeed, as the 
            \* neuron has just been created in the same atomic block. We'll call assert
            \* instead of await here, to check that
            assert neuron_id \notin locks;
            locks := locks \union {neuron_id};
            neuron_id_by_account := account :> neuron_id @@ neuron_id_by_account;
            neuron := neuron_id :> [ cached_stake |-> 0, account |-> account, fees |-> 0, maturity |-> 0 ] @@ neuron;
            \* send_request(self, OP_QUERY_BALANCE, balance_query(account));
            governance_to_ledger := Append(governance_to_ledger, request(self, account_balance(account)));
        };
        };
    WaitForBalanceQuery:
        \* Note that the "with" construct implicitly awaits until the set of values to draw from is non-empty
        with(answer \in { resp \in ledger_to_governance : resp.caller = self }) {
            ledger_to_governance := ledger_to_governance \ {answer};
            if(answer.response = Variant("Fail", UNIT)) {
                neuron := Remove_Arguments(neuron, {neuron_id});
                neuron_id_by_account := Remove_Arguments(neuron_id_by_account, {account});
            } else {
                with (b = VariantGetOrElse("BalanceQueryOk", answer.response, 0)) {
                    if(b >= MIN_STAKE) {
                        neuron := [neuron EXCEPT ![neuron_id] = [@ EXCEPT !.cached_stake = b] ]
                    } else {
                        neuron := Remove_Arguments(neuron, {neuron_id});
                        neuron_id_by_account := Remove_Arguments(neuron_id_by_account, {account});
                    };
                    locks := locks \ {neuron_id};
                };
            };
        };
        cn_reset_local_vars();
    };

}
*)
\* BEGIN TRANSLATION (chksum(pcal) = "21884f75" /\ chksum(tla) = "dd0a7814")
VARIABLES neuron, neuron_id_by_account, locks, governance_to_ledger, 
          ledger_to_governance, pc, account_id, neuron_id

vars == << neuron, neuron_id_by_account, locks, governance_to_ledger, 
           ledger_to_governance, pc, account_id, neuron_id >>

ProcSet == (Claim_Neuron_Process_Ids)

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        (* Process Claim_Neuron *)
        /\ account_id = [self \in Claim_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        /\ neuron_id = [self \in Claim_Neuron_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "ClaimNeuron1"]

ClaimNeuron1(self) == /\ pc[self] = "ClaimNeuron1"
                      /\ \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                            /\ UNCHANGED <<neuron, neuron_id_by_account, locks, governance_to_ledger, account_id, neuron_id>>
                         \/ /\ \E aid \in Governance_Account_Ids \ DOMAIN(neuron_id_by_account):
                                 /\ account_id' = [account_id EXCEPT ![self] = aid]
                                 /\ neuron_id' = [neuron_id EXCEPT ![self] = FRESH_NEURON_ID(DOMAIN(neuron))]
                                 /\ Assert(neuron_id'[self] \notin locks, 
                                           "Failure of assertion at line 71, column 13.")
                                 /\ locks' = (locks \union {neuron_id'[self]})
                                 /\ neuron_id_by_account' = (account_id'[self] :> neuron_id'[self] @@ neuron_id_by_account)
                                 /\ neuron' = (neuron_id'[self] :> [ cached_stake |-> 0, account |-> account_id'[self], fees |-> 0, maturity |-> 0 ] @@ neuron)
                                 /\ governance_to_ledger' = Append(governance_to_ledger, request(self, account_balance(account_id'[self])))
                            /\ pc' = [pc EXCEPT ![self] = "WaitForBalanceQuery"]
                      /\ UNCHANGED ledger_to_governance

WaitForBalanceQuery(self) == /\ pc[self] = "WaitForBalanceQuery"
                             /\ \E answer \in { resp \in ledger_to_governance : resp.caller = self }:
                                  /\ ledger_to_governance' = ledger_to_governance \ {answer}
                                  /\ IF answer.response = Variant("Fail", UNIT)
                                        THEN /\ neuron' = Remove_Arguments(neuron, {neuron_id[self]})
                                             /\ neuron_id_by_account' = Remove_Arguments(neuron_id_by_account, {account_id[self]})
                                             /\ locks' = locks
                                        ELSE /\ LET b == answer.value IN
                                                  /\ IF b >= MIN_STAKE
                                                        THEN /\ neuron' = [neuron EXCEPT ![neuron_id[self]] = [@ EXCEPT !.cached_stake = b] ]
                                                             /\ UNCHANGED neuron_id_by_account
                                                        ELSE /\ neuron' = Remove_Arguments(neuron, {neuron_id[self]})
                                                             /\ neuron_id_by_account' = Remove_Arguments(neuron_id_by_account, {account_id[self]})
                                                  /\ locks' = locks \ {neuron_id[self]}
                             /\ account_id' = [account_id EXCEPT ![self] = DUMMY_ACCOUNT]
                             /\ neuron_id' = [neuron_id EXCEPT ![self] = 0]
                             /\ pc' = [pc EXCEPT ![self] = "Done"]
                             /\ UNCHANGED governance_to_ledger

Claim_Neuron(self) == ClaimNeuron1(self) \/ WaitForBalanceQuery(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Claim_Neuron_Process_Ids: Claim_Neuron(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

====
