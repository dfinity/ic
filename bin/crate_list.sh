#!/bin/bash
bazel_deps_query() {
    bazel query 'deps(@crate_index//:all, 1)' --output package --notool_deps --noimplicit_deps --nohost_deps --ui_event_filters=-WARNING,-ERROR,-INFO
}

# Function to extract crate name and fetch data
process_crate() {
    local line="$1"
    
    # Extract crate name using 'sed'
    crate_name=$(echo "$line" | sed -E 's/@crate_index__([a-zA-Z0-9_-]+)-[0-9.]+\/\//\1/')

    # Check if extraction was successful
    if [[ -z "$crate_name" ]]; then
        # echo "Failed to extract crate name from: $line"
        return
    fi

    # echo "Fetching data for crate: $crate_name"

    # Fetch crate metadata from crates.io
    response=$(curl -s "https://crates.io/api/v1/crates/$crate_name")

    # Extract relevant info (categories or keywords)
    category_or_keyword=$(echo "$response" | jq -r '
      (.keywords[]? | select(.id | IN("crypto", "encryption", "security")) | "true") // 
      (.categories[]? | select(.id | IN("cryptography")) | "true") // 
      empty
    ' | head -n1)  # Stop after the first match

    # Print result if a category or keyword match is found
    if [[ -n "$category_or_keyword" ]]; then
        echo "$crate_name"
    fi
}

# Run the command and process each line
bazel_deps_query | while IFS= read -r line; do
    process_crate "$line"
done

# process_crate "blake2"
# Current list 
#
# bip32
# bitcoin
# bitcoin
# bitcoincore-rpc
# chacha20poly1305
# curve25519-dalek
# ed25519-dalek
# ethers-core
# hkdf
# hmac
# ic-canister-sig-creation
# ic-certified-map
# k256
# p256
# pem
# pkcs8
# ring
# ripemd
# rsa
# rustls
# rustls-pemfile
# secp256k1
# sha2
# sha3
# signature
# subtle
# tokio-rustls
# wycheproof
# x509-cert
# x509-parser
# zeroize