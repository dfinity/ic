##: claim_or_refresh
## Usage: $1 <NETWORK> <NEURON_ID>
##  Claim or refresh an NNS neuron with a particular ID
##  NETWORK: The network to use.
##  NEURON_ID: The neuron id to claim or refresh.
## Example: claim_or_refresh ic 1234567890
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

##: nns_account_for_neuron_id
## Usage: $1 <NETWORK> <NEURON_ID>
##  Get the account for a neuron with a particular ID
## Your DFX identity must be set to a neuron that is authorized
## to query the full neuron record.  See nns_get_full_neuron
nns_account_for_neuron_id() {
    local network=$1
    local neuron_id=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/nns/governance/canister/governance.did"

    local full_neuron=$(nns_get_full_neuron "$network" "$neuron_id")
     if [[ "$full_neuron" == *"error_message"* ]]; then
        echo "Error: $full_neuron"
        return 1
    fi

    local account=$(echo "$full_neuron" | grep "account = blob" | awk '{print $4}' | tr -d '";')

    local hex=$(candid_blob_to_hex "$account")
    dfx ledger account-id --of-principal $(nns_canister_id governance) --subaccount "$hex"
}

 # account = blob "\der\93\daH/\ff\f4\1f\fe\9e\05\8c\1f\0b\c4X\f9\15\c2p\f3\90\80\ff\ecO\0d%S\0c\1a";

candid_blob_to_hex() {
    local raw_string=$1

    python3 -c '
import sys

def parse_candid_escapes(s):
    i = 0
    out = bytearray()
    while i < len(s):
        if s[i] == "\\":
            if i + 1 < len(s):
                hex_digits = []
                j = i + 1
                while j < len(s) and len(hex_digits) < 2 and s[j] in "0123456789abcdefABCDEF":
                    hex_digits.append(s[j])
                    j += 1
                if hex_digits:
                    out.append(int("".join(hex_digits), 16))
                    i = j
                    continue
            i += 1
        else:
            out.append(ord(s[i]))
            i += 1
    return bytes(out)

if __name__ == "__main__":
    raw_string = sys.argv[1]
    parsed_bytes = parse_candid_escapes(raw_string)
    print(parsed_bytes.hex())
    ' "$raw_string"
}