------------ MODULE Claim_Neuron ------------
EXTENDS TLC, Sequences, Naturals, FiniteSets, Variants

CONSTANT
    FRESH_NEURON_ID(_)

CONSTANTS 
    Governance_Account_Ids, 
    Minting_Account_Id,
    Neuron_Ids

CONSTANTS 
    Claim_Neuron_Process_Ids

CONSTANTS 
    \* Minimum stake a neuron can have
    MIN_STAKE

OP_ACCOUNT_BALANCE == "account_balance"
ACCOUNT_BALANCE_FAIL == "Err"
DUMMY_ACCOUNT == ""

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
    account_id := DUMMY_ACCOUNT;
    balance := 0;
    neuron_id := 0;
}


\* Copied directly from formal-models/tla/governance-ledger
\* A Claim_Neuron process simulates a call to claim_neuron
process ( Claim_Neuron \in Claim_Neuron_Process_Ids )
    variable 
        \* The account_id is an argument to the canister call; we let it be chosen non-deteministically 
        account_id = Minting_Account_Id;
        \* The neuron_id will be set later on to a fresh value
        neuron_id = 0;
    { 
    ClaimNeuron1:
        with(aid \in  Governance_Account_Ids \ DOMAIN(neuron_id_by_account)) {
            account_id := aid;
            \* Get a fresh neuron ID
            neuron_id := neuron_count;
            neuron_count := neuron_count + 1;
            \* The Rust code tries to obtain a lock; this should always succeed, as the 
            \* neuron has just been created in the same atomic block. We'll call assert
            \* instead of await here, to check that
            assert neuron_id \notin locks;
            locks := locks \union {neuron_id};
            add_neuron(neuron_id, account_id);
            send_request(self, OP_QUERY_BALANCE, balance_query(account_id));
        };

    ClaimNeuron2:
        \* Note that the "with" construct implicitly awaits until the set of values to draw from is non-empty
        with(r \in { r2 \in ledger_to_governance : r2.caller = self }; b = r.response_value.bal ) {
            ledger_to_governance := ledger_to_governance \ {r};
            if(b >= MIN_STAKE) {
                neuron := [neuron EXCEPT ![neuron_id] = [@ EXCEPT !.cached_stake = b] ]
            } else {
                remove_neuron(neuron_id, account_id);
            };
            locks := locks \ {neuron_id};
        };
    };

}
*)
