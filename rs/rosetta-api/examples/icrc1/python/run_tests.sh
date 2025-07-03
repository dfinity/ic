#!/bin/bash
# This script runs all ICRC-1 example scripts against a local Rosetta API
# endpoint to verify they're working properly.

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters for passed and failed tests
PASSED=0
FAILED=0
TEST_RESULT=0

# Function to run a test and track results
run_test() {
    local script=$1
    local args=$2
    local description=$3

    echo -e "${BLUE}======================================================${NC}"
    echo -e "Running: ${YELLOW}$script${NC}"
    echo -e "Description: $description"
    echo -e "Command: python3 $script $args"
    echo ""

    # Run the script
    python3 "$script" $args

    # Check the exit status
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ Test passed${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "\n${RED}✗ Test failed${NC}"
        FAILED=$((FAILED + 1))
        TEST_RESULT=1
    fi
}

print_usage() {
    echo -e "${BLUE}======================================================${NC}"
    echo "ICRC-1 Rosetta API Test Runner"
    echo -e "${BLUE}======================================================${NC}"
    echo ""
    echo "This script runs all the example scripts to test the ICRC-1 Rosetta API."
    echo ""
    echo "Usage: ./run_tests.sh [options]"
    echo ""
    echo "Required arguments:"
    echo "  --node-address URL      Rosetta API endpoint URL (e.g., http://localhost:8082)"
    echo "  --canister-id ID        ICRC-1 canister ID"
    echo "  --principal-id ID       Principal ID to use for balance checks"
    echo ""
    echo "Optional arguments for transfer tests:"
    echo "  --private-key-path PATH Private key file (needed for transfers)"
    echo "  --to-principal ID       Recipient principal ID (needed for transfers)"
    echo "  --amount VALUE          Amount to transfer (default: 100)"
    echo "  --fee VALUE             Fee to pay (default: 10)"
    echo ""
    echo "Examples:"
    echo "  # Run basic tests (read-only)"
    echo "  ./run_tests.sh --node-address http://localhost:8082 \\"
    echo "              --canister-id 3jkp5-oyaaa-aaaaj-azwqa-cai \\"
    echo "              --principal-id 6olso-qqls6-4kfi5-tmm6c-3g2sp-pxis2-sifzu-qgdm7-26imm-zbsyn-qae"
    echo ""
    echo "  # Run all tests including transfer"
    echo "  ./run_tests.sh --node-address http://localhost:8082 \\"
    echo "              --canister-id 3jkp5-oyaaa-aaaaj-azwqa-cai \\"
    echo "              --principal-id 6olso-qqls6-4kfi5-tmm6c-3g2sp-pxis2-sifzu-qgdm7-26imm-zbsyn-qae \\"
    echo "              --private-key-path ./my_key.pem \\"
    echo "              --to-principal jge5w-unltc-lodkf-bexod-acxbr-rqa23-33m3t-jxmkd-lobix-h3spx-uqe \\"
    echo "              --amount 100 \\"
    echo "              --fee 10"
    echo -e "${BLUE}======================================================${NC}"
}

# Check if help was requested
if [[ "$1" == "-h" || "$1" == "--help" || $# -eq 0 ]]; then
    print_usage
    exit 0
fi

# Flag to track if we have the required arguments
HAS_CANISTER_ID=false
HAS_NODE_ADDRESS=false
HAS_PRINCIPAL_ID=false

# Store the actual values for each parameter
NODE_ADDRESS=""
CANISTER_ID=""
PRINCIPAL_ID=""
PRIVATE_KEY_PATH=""
TO_PRINCIPAL=""
AMOUNT=""
FEE=""

# Parse arguments
for ((i = 1; i <= $#; i++)); do
    if [[ "${!i}" == "--canister-id" ]]; then
        HAS_CANISTER_ID=true
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            CANISTER_ID="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--node-address" ]]; then
        HAS_NODE_ADDRESS=true
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            NODE_ADDRESS="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--principal-id" ]]; then
        HAS_PRINCIPAL_ID=true
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            PRINCIPAL_ID="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--private-key-path" ]]; then
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            PRIVATE_KEY_PATH="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--to-principal" ]]; then
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            TO_PRINCIPAL="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--amount" ]]; then
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            AMOUNT="${!next_i}"
        fi
    fi
    if [[ "${!i}" == "--fee" ]]; then
        next_i=$((i + 1))
        if [[ $next_i -le $# ]]; then
            FEE="${!next_i}"
        fi
    fi
done

# Check if we have the required arguments
if [[ "$HAS_CANISTER_ID" == "false" || "$HAS_NODE_ADDRESS" == "false" || "$HAS_PRINCIPAL_ID" == "false" ]]; then
    echo -e "${RED}Error: Missing required arguments.${NC}"
    print_usage
    exit 1
fi

# Create specific args for each command
NETWORK_INFO_ARGS="--node-address $NODE_ADDRESS --canister-id $CANISTER_ID"
READ_BLOCKS_ARGS="--node-address $NODE_ADDRESS --canister-id $CANISTER_ID"
BALANCE_ARGS="--node-address $NODE_ADDRESS --canister-id $CANISTER_ID --principal-id $PRINCIPAL_ID"

# Check if we have transfer arguments
HAS_TRANSFER_ARGS=false
if [[ -n "$PRIVATE_KEY_PATH" && -n "$TO_PRINCIPAL" && -n "$AMOUNT" && -n "$FEE" ]]; then
    HAS_TRANSFER_ARGS=true
    TRANSFER_ARGS="--node-address $NODE_ADDRESS --canister-id $CANISTER_ID --private-key-path $PRIVATE_KEY_PATH --to-principal $TO_PRINCIPAL --amount $AMOUNT --fee $FEE --signature-type ecdsa"
fi

echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}ICRC-1 Rosetta API Tests${NC}"
echo -e "${BLUE}======================================================${NC}"

# Run the non-transfer tests
run_test "get_network_info.py" "$NETWORK_INFO_ARGS" "Fetch network information from the Rosetta API"
run_test "read_blocks.py" "$READ_BLOCKS_ARGS" "Read blocks from the ICRC-1 ledger via Rosetta API"
run_test "get_account_balance.py" "$BALANCE_ARGS" "Get balance for a principal via Rosetta API"

# Run transfer test if we have all the required arguments
if [[ "$HAS_TRANSFER_ARGS" == "true" ]]; then
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${YELLOW}Running Transfer Test${NC}"

    run_test "transfer.py" "$TRANSFER_ARGS" "Transfer tokens between principals"
else
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${YELLOW}Skipping Transfer Test${NC}"
    echo "To run transfer tests, provide --private-key-path, --to-principal, --amount, and --fee arguments"
fi

# Print summary
echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}Test Summary${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

if [[ "$FAILED" -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed.${NC}"
fi

echo -e "${BLUE}======================================================${NC}"
exit $TEST_RESULT
