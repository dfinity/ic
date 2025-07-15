#!/bin/bash
# run_tests.sh - Run Rosetta API tests in a virtual environment
#
# This script:
# 1. Checks if virtualenv is installed
# 2. Creates a virtual environment
# 3. Installs dependencies from requirements.txt
# 4. Runs test_all.py with any provided arguments
# 5. Deactivates and cleans up the virtual environment

set -e # Exit immediately if a command exits with a non-zero status

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Virtual environment name
VENV_NAME=".rosetta_venv"

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}    Internet Computer Rosetta API Test Runner    ${NC}"
echo -e "${BLUE}======================================================${NC}"

# Check if Python is installed
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: Python 3 is not installed. Please install Python 3 and try again.${NC}"
    exit 1
fi

# Check if virtualenv is installed
if ! command -v virtualenv &>/dev/null; then
    echo -e "${YELLOW}virtualenv is not installed. Trying to install it...${NC}"
    pip3 install virtualenv

    # Check again if virtualenv is installed
    if ! command -v virtualenv &>/dev/null; then
        echo -e "${RED}Failed to install virtualenv. Please install it manually:${NC}"
        echo -e "${YELLOW}pip3 install virtualenv${NC}"
        exit 1
    fi
fi

# Check for existing virtual environment and remove if necessary
if [ -d "$VENV_NAME" ]; then
    echo -e "${YELLOW}Removing existing virtual environment...${NC}"
    rm -rf "$VENV_NAME"
fi

echo -e "${GREEN}Creating virtual environment...${NC}"
virtualenv "$VENV_NAME"

# Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source "$VENV_NAME/bin/activate"

# Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
pip install -r requirements.txt

# Run the test script with all provided arguments as-is
echo -e "${GREEN}Running tests...${NC}"
echo -e "${YELLOW}Command: python test_all.py $@${NC}"
echo -e "${BLUE}------------------------------------------------------${NC}"
python test_all.py "$@"
TEST_RESULT=$?
echo -e "${BLUE}------------------------------------------------------${NC}"

# Deactivate virtual environment
echo -e "${GREEN}Deactivating virtual environment...${NC}"
deactivate

# Cleanup
echo -e "${GREEN}Cleaning up...${NC}"
rm -rf "$VENV_NAME"

# Final message
if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}All tests completed successfully!${NC}"
else
    echo -e "${RED}Tests completed with failures.${NC}"
fi

echo -e "${BLUE}======================================================${NC}"
exit $TEST_RESULT
