##: nns_claim_or_refresh
## Usage: $1 <NETWORK> <NEURON_ID>
##  Claim or refresh an NNS neuron with a particular ID
##  NETWORK: The network to use.
##  NEURON_ID: The neuron id to claim or refresh.
## Example: nns_claim_or_refresh ic 1234567890
nns_claim_or_refresh() {
    local network=$1
    local neuron_id=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/nns/governance/canister/governance.did"

    dfx canister \
        --network ic \
        call \
        --candid "$GOV_DID" \
        rrkah-fqaaa-aaaaa-aaaaq-cai \
        manage_neuron "(
        record {
          id = opt record { id = ${neuron_id}: nat64 };
          command = opt variant {
            ClaimOrRefresh = record {
              controller = null;
              by = opt variant {
                NeuronIdOrSubaccount = record { }
              }
            }
          }
        }
      )"
}

##: nns_list_my_neurons
## Usage: $1 <NNS_URL>
## List the neurons owned by the current dfx identity
nns_list_my_neurons() {

    local NNS_URL=$1 # usually NNS_URL

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/nns/governance/canister/governance.did"

    __dfx -q canister --network $NNS_URL call \
        --candid $GOV_DID \
        $GOVERNANCE list_neurons \
        "(
           record {
             page_size = null;
             include_public_neurons_in_full_neurons = null;
             neuron_ids = vec {};
             page_number = null;
             include_empty_neurons_readable_by_caller = null;
             neuron_subaccounts = null;
             include_neurons_readable_by_caller = true;
           },
         )"

}
