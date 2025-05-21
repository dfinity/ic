---- MODULE Governance ----

EXTENDS TLC, FiniteSetsExt, Naturals, Variants, Sequences

\*******************************************************************************
\* Behavior described in the submodules
\*******************************************************************************

DUMMY_ACCOUNT == ""

CONSTANTS
    Minting_Account_Id,
    Governance_Account_Ids,
    Account_Ids,
    MIN_STAKE,
    TRANSACTION_FEE,
    MATURITY_BASIS_POINTS,
    MIN_DISBURSEMENT

POSSIBLE_DISBURSE_AMOUNTS(neurons, nid) == 0..neurons[nid].cached_stake + 1

CONSTANTS
    Claim_Neuron_Process_Ids,
    Disburse_Maturity_Process_Ids,
    Disburse_Maturity_Timer_Process_Ids,
    Disburse_Neuron_Process_Ids,
    Disburse_To_Neuron_Process_Ids,
    Merge_Neurons_Process_Ids,
    Refresh_Neuron_Process_Ids,
    Spawn_Neuron_Process_Ids,
    Spawn_Neurons_Process_Ids,
    Split_Neuron_Process_Ids

FRESH_NEURON_ID(neuron_ids) == Max(neuron_ids \union {0}) + 1

VARIABLES
    neuron,
    \* Used to decide whether we should refresh or claim a neuron
    neuron_id_by_account,
    \* The set of currently locked neurons
    locks,
    \* The queue of messages sent from the governance canister to the ledger canister
    governance_to_ledger,
    ledger_to_governance

VARIABLES
    spawning_neurons

VARIABLES pc,
          \* Merge_Neuron
          source_neuron_id, target_neuron_id, fees_amount, amount_to_target,
          \* Claim_Neuron
          account,
          \* Claim_Neuron, Disburse_Neuron and Disburse_Maturity_Timer
          neuron_id,
          \* Disburse_Neuron and Disburse_To_Neuron
          disburse_amount,
          \* Disburse_Neuron
          to_account,
          \* Disburse_To_Neuron
          child_account_id, child_neuron_id, parent_neuron_id,
          \* Spawn_Neurons
          ready_to_spawn_ids,
          \* Split_Neuron
          sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id,
          \* Disburse_Maturity_Timer
          current_disbursement

global_non_ledger_vars == << neuron, neuron_id_by_account, locks, spawning_neurons >>
local_vars == <<
    pc,
    source_neuron_id, target_neuron_id, fees_amount, amount_to_target, account, neuron_id, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id,
    sn_child_account_id,
    current_disbursement
    >>

Claim == INSTANCE Claim_Neuron
Disburse == INSTANCE Disburse_Neuron
Disburse_To == INSTANCE Disburse_To_Neuron
Disburse_Maturity == INSTANCE Disburse_Maturity
Disburse_Maturity_Timer == INSTANCE Disburse_Maturity_Timer
Merge == INSTANCE Merge_Neurons
Refresh == INSTANCE Refresh_Neuron
Spawn == INSTANCE Spawn_Neuron
Spawn_Neurons == INSTANCE Spawn_Neurons
Split == INSTANCE Split_Neuron

\*******************************************************************************
\* Environment (ledger, rest of governance canister)
\*******************************************************************************

CONSTANTS
    NUMBER_OF_TRANSFERS_CAP,
    INITIAL_MAX_BALANCE,
    MAX_NEURON_FEE,
    MAX_MATURITY

CONSTANTS
    User_Account_Ids

VARIABLES
    balances,
    minted,
    burned,
    total_rewards,
    nr_transfers

ledger_vars == << balances, minted, burned, nr_transfers >>
env_vars == << ledger_vars, total_rewards >>

Ledger_Init ==
    /\ balances = [a \in Governance_Account_Ids \union {Minting_Account_Id} |-> 0] @@ [a \in User_Account_Ids |-> INITIAL_MAX_BALANCE]
    /\ minted = 0
    /\ burned = 0
    /\ nr_transfers = 0
    /\ total_rewards = 0

response(caller, response_val) == [caller |-> caller, response |-> response_val]

Ledger_Process_Governance_Request ==
    /\ governance_to_ledger /= <<>>
    /\ governance_to_ledger' = Tail(governance_to_ledger)
    /\
      LET
        req == Head(governance_to_ledger)
      IN
        \* Spontaneous rejection, regardless of what the request was
        \/
            /\ ledger_to_governance' = ledger_to_governance \union {response(req.caller, Variant("Fail", UNIT))}
            /\ UNCHANGED << minted, burned, balances, nr_transfers, total_rewards >>
        \* Actual processing of messages
        \/
          LET
            margs == req.method_and_args
            t == VariantTag(margs)
            caller == req.caller
          IN
            \/
                /\ t = "AccountBalance"
                /\ UNCHANGED << minted, burned, balances, nr_transfers, total_rewards >>
                /\
                  LET
                    acc == VariantGetUnsafe(t, margs).account
                    \* We don't explicitly cover the case of asking for an invalid account here, as we only
                    \* expect the governance to ask for valid accounts. If an invalid request would happen,
                    \* model checking would fail so we'd catch in anyways.
                    resp == Variant("BalanceQueryOk", balances[acc])
                  IN
                       /\ ledger_to_governance' = ledger_to_governance \union {response(caller, resp)}
            \/
                /\ t = "Transfer"
                /\ UNCHANGED << nr_transfers, total_rewards >>
                /\
                  LET
                    arg == VariantGetUnsafe(t, margs)
                    from_acc == arg.from
                    to_acc == arg.to
                    amnt == arg.amount
                    fee == arg.fee
                    is_invalid_transfer ==
                        \/
                          /\ from_acc /= Minting_Account_Id
                          /\ to_acc /= Minting_Account_Id
                          /\ fee < TRANSACTION_FEE
                        \/ from_acc = Minting_Account_Id /\ to_acc = Minting_Account_Id
                        \/ from_acc = Minting_Account_Id /\ fee /= 0
                        \/ to_acc = Minting_Account_Id /\ fee /= 0
                        \/ to_acc = Minting_Account_Id /\ amnt < TRANSACTION_FEE
                        \/ fee + amnt > balances[from_acc]
                  IN
                    \/
                        /\ is_invalid_transfer
                        /\ ledger_to_governance' = ledger_to_governance \union {response(caller, Variant("Fail", UNIT))}
                        /\ UNCHANGED << minted, burned, balances >>
                    \/
                        /\ ~is_invalid_transfer
                        /\ balances' = [balances EXCEPT
                                ![from_acc] = @ - (fee + amnt),
                                ![to_acc] = @ + amnt]
                        /\ ledger_to_governance' = (ledger_to_governance \union {response(caller, Variant("TransferOk", UNIT))})
                        /\ burned' = burned + fee + (IF to_acc = Minting_Account_Id THEN amnt ELSE 0)
                        /\ IF from_acc = Minting_Account_Id
                            THEN minted' = minted + amnt
                            ELSE UNCHANGED minted

Ledger_User_Transfer ==
    /\ nr_transfers < NUMBER_OF_TRANSFERS_CAP
    /\ \E sender \in { a \in Account_Ids \ Governance_Account_Ids : balances[a] > 0 }:
       \E amnt \in 1..balances[sender], recipient \in Governance_Account_Ids:
        /\ balances' = [balances EXCEPT ![sender] = @ - amnt, ![recipient] = @ + amnt]
        /\ nr_transfers' = nr_transfers + 1
        /\ UNCHANGED <<minted, burned, governance_to_ledger, ledger_to_governance>>

\*******************************************************************************
\* Putting it all together
\*******************************************************************************

Init == (* Global variables *)
        /\ neuron \in [{} -> {}]
        /\ neuron_id_by_account \in [{} -> {}]
        /\ locks = {}
        /\ governance_to_ledger = <<>>
        /\ ledger_to_governance = {}
        /\ spawning_neurons = FALSE
        (* Process Claim_Neuron *)
        /\ account = [self \in Claim_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        (* Process Disburse_Neuron *)
        /\ to_account = [self \in Disburse_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        (* Process Disburse_To_Neuron *)
        /\ parent_neuron_id = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
        /\ child_account_id = [self \in Disburse_To_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        /\ child_neuron_id = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
        (* Process Merge_Neurons *)
        /\ source_neuron_id = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ target_neuron_id = [self \in Merge_Neurons_Process_Ids |-> 0]
        /\ amount_to_target = [self \in Merge_Neurons_Process_Ids |-> 0]
        (* Process Spawn_Neurons *)
        /\ ready_to_spawn_ids = [self \in Spawn_Neurons_Process_Ids |-> {}]
        (* Process Split_Neuron *)
        /\ sn_parent_neuron_id = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_amount = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_child_neuron_id = [self \in Split_Neuron_Process_Ids |-> 0]
        /\ sn_child_account_id = [self \in Split_Neuron_Process_Ids |-> DUMMY_ACCOUNT]
        \* Disburse_Maturity_Timer
        /\ current_disbursement = [self \in Disburse_Maturity_Timer_Process_Ids |-> Disburse_Maturity_Timer!DUMMY_DISBURSEMENT]
        \* Mixed
        /\ disburse_amount = [self \in Disburse_To_Neuron_Process_Ids |-> 0]
         @@ [self \in Disburse_Neuron_Process_Ids |-> 0]
        /\ neuron_id = [self \in Claim_Neuron_Process_Ids |-> 0]
           @@ [self \in Disburse_Neuron_Process_Ids |-> 0]
           @@ [self \in Spawn_Neurons_Process_Ids |-> 0]
           @@ [self \in Refresh_Neuron_Process_Ids |-> 0]
           @@ [self \in Disburse_Maturity_Timer_Process_Ids |-> 0]
        /\ fees_amount = [self \in Merge_Neurons_Process_Ids |-> 0]
           @@ [self \in Disburse_Neuron_Process_Ids |-> 0]
        /\ pc = [self \in Split_Neuron_Process_Ids |-> "SplitNeuron1"]
            @@ [self \in Spawn_Neurons_Process_Ids |-> "SpawnNeurons_Start"]
            @@ [self \in Spawn_Neuron_Process_Ids |-> "SpawnNeurons_Start"]
            @@ [self \in Merge_Neurons_Process_Ids |-> "MergeNeurons_Start"]
            @@ [self \in Disburse_To_Neuron_Process_Ids |-> "DisburseToNeuron"]
            @@ [self \in Disburse_Neuron_Process_Ids |-> "DisburseNeuron1"]
            @@ [self \in Claim_Neuron_Process_Ids |-> "ClaimNeuron1"]
            @@ [self \in Refresh_Neuron_Process_Ids |-> "RefreshNeuron1"]
            @@ [self \in Disburse_Maturity_Timer_Process_Ids |-> "Disburse_Maturity_Timer_Start"]
        /\ Ledger_Init

Change_Neuron_Fee ==
    \* Note that we can change the fee even while the neuron is locked
    \E nid \in DOMAIN(neuron):
        \E new_fee_value \in 0..Min({MAX_NEURON_FEE, neuron[nid].cached_stake}):
            \* Does the model need to be more strict on how fees can be decreased?
            /\ neuron' = [neuron EXCEPT ![nid].fees = new_fee_value]
            /\ UNCHANGED <<neuron_id_by_account, locks, governance_to_ledger, ledger_to_governance, spawning_neurons, env_vars, local_vars >>

Increase_Neuron_Maturity ==
    \E nid \in DOMAIN(neuron):
        \* We assume that neurons whose cached stake is 0 don't get maturity.
        \* This is a bit harsh, but otherwise we end up having to model the spawning
        \* state, which would increase the load on model checking further.
        /\ neuron[nid].cached_stake > 0
        /\ \E new_maturity \in (neuron[nid].maturity+1)..MAX_MATURITY:
            /\ total_rewards' = total_rewards + new_maturity - neuron[nid].maturity
            /\ neuron' = [neuron EXCEPT ![nid].maturity = new_maturity]
            /\ UNCHANGED <<neuron_id_by_account, locks, governance_to_ledger, ledger_to_governance, spawning_neurons, ledger_vars, local_vars >>


Next ==
    \* Combine the transitions of all the submodules, by taking the disjunction of the transitions of any submodule.
    \* Additionally, each disjunct leaves unchanged the variables that are not used by the submodule.
    \/ Claim!Next /\  UNCHANGED <<env_vars, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Disburse!Next /\ UNCHANGED <<env_vars, source_neuron_id, target_neuron_id, amount_to_target, account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Disburse_To!Next /\ UNCHANGED <<env_vars, source_neuron_id, target_neuron_id, to_account, account, fees_amount, amount_to_target, neuron_id, account, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Merge!Next /\ UNCHANGED <<env_vars, neuron_id, disburse_amount, to_account, account, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Refresh!Next /\ UNCHANGED << env_vars, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, account, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement  >>
    \/ Spawn!Next /\ UNCHANGED pc /\ UNCHANGED <<env_vars, neuron_id, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, disburse_amount, to_account, account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Spawn_Neurons!Next /\ UNCHANGED <<env_vars, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, disburse_amount, to_account, account, child_account_id, child_neuron_id, parent_neuron_id, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement >>
    \/ Split!Next /\ UNCHANGED << env_vars, neuron_id, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, account, disburse_amount, to_account, ready_to_spawn_ids, child_account_id, child_neuron_id, parent_neuron_id, current_disbursement  >>
    \/ Disburse_Maturity!Next /\ UNCHANGED << env_vars, neuron_id, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, account, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id, current_disbursement, pc >>
    \* Disburse_Maturity_Timer!Next /\ UNCHANGED << env_vars, source_neuron_id, target_neuron_id, fees_amount, amount_to_target, account, disburse_amount, to_account, child_account_id, child_neuron_id, parent_neuron_id, ready_to_spawn_ids, sn_parent_neuron_id, sn_amount, sn_child_neuron_id, sn_child_account_id >>
    \* "Environment" transitions
    \/ Ledger_Process_Governance_Request /\ UNCHANGED << global_non_ledger_vars, local_vars >>
    \/ Ledger_User_Transfer /\ UNCHANGED << global_non_ledger_vars, local_vars, governance_to_ledger, ledger_to_governance, total_rewards >>
    \/ Change_Neuron_Fee
    \/ Increase_Neuron_Maturity

\*******************************************************************************
\* Properties
\*******************************************************************************

\* A sanity check: we can actually get a non-zero stake in a neuron
Can_Stake_Sanity == \A n \in DOMAIN(neuron) : neuron[n].cached_stake = 0

Can_Decrease_Stake_Sanity == [][\A n \in DOMAIN(neuron) \cap DOMAIN(neuron') : neuron[n].cached_stake <= neuron'[n].cached_stake]_<<global_non_ledger_vars, local_vars, env_vars>>

\* This may be temporarily violated when the neuron is locked
\* Cached_Stake_Capped_By_Balance == \A n \in DOMAIN(neuron) :
\*     neuron[n].cached_stake <= balances[neuron[n].account]

\* This is a s speculative invariant that turned out not to hold, as neurons can incur
\* a fee even while, say, merging.
\* Fees_Smaller_Than_Cached_Stake == \A n \in DOMAIN(neuron):
\*     neuron[n].fees <= neuron[n].cached_stake

Cached_Stake_Capped_By_Balance_When_Not_Locked == \A n \in DOMAIN(neuron) :
    n \notin locks => neuron[n].cached_stake <= balances[neuron[n].account]

Regular_Balances_Sum == SumSet(Range([a \in DOMAIN(balances) \ {Minting_Account_Id} |-> balances[a]]))
Total_Balance_Is_Constant_Modulo_Fees == Regular_Balances_Sum + burned - minted = Regular_Balances_Sum' + burned' - minted'

\* This invariant should prevent double spending of maturity
Total_Minting_Does_Not_Exceed_Rewards == minted <= total_rewards


Neurons_Have_Unique_Accounts == \A n1, n2 \in DOMAIN(neuron) :
    n1 /= n2 => neuron[n1].account /= neuron[n2].account

Neuron_And_Account_Id_By_Neuron_Coherent == \A n \in DOMAIN(neuron), a \in DOMAIN(neuron_id_by_account):
    /\ neuron_id_by_account[neuron[n].account] = n
    /\ neuron[neuron_id_by_account[a]].account = a

Cached_Stake_Not_Underflowing == \A n \in DOMAIN(neuron): neuron[n].cached_stake >= 0

\* This doesn't hold, and we probably don't want it as is (maybe: either 0 or this)
\* Neurons_Have_At_Least_Min_Stake == \A n \in DOMAIN(neuron) :
\*     n \notin locks => neuron[n].cached_stake >= MIN_STAKE

Ready_To_Spawn_Ids_Exist == (UNION Range(ready_to_spawn_ids)) \subseteq DOMAIN(neuron)

\*******************************************************************************
\* Symmetry optimizations for model checking
\*******************************************************************************

Symmetry_Sets == { Claim_Neuron_Process_Ids,
    \* Refresh_Neuron_Process_Ids,
    Disburse_Neuron_Process_Ids,
    Spawn_Neuron_Process_Ids,
    Disburse_To_Neuron_Process_Ids,
    Split_Neuron_Process_Ids,
    Governance_Account_Ids,
    \* Change_Neuron_Fee_Process_Ids,
    \* Increase_Neuron_Maturity_Process_Ids,
    User_Account_Ids
}
symmetry_permutations == UNION { Permutations(S) : S \in Symmetry_Sets }


====
