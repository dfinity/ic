// SPDX-License-Identifier: Apache-2.0

pragma solidity 0.8.18;

/**
 * @title A helper smart contract for ETH <-> ckETH conversion.
 * @notice This smart contract deposits incoming ETH to the ckETH minter account and emits deposit events.
 */
contract CkEthDeposit {
    address payable private cketh_minter_main_address;
    uint256 private last_block_number;
    uint256 private event_counter;

    event ReceivedEth(address indexed from, uint256 value, bytes32 indexed principal);

    /**
     * @dev Set cketh_minter_main_address.
     */
    constructor(address _cketh_minter_main_address) {
        cketh_minter_main_address = payable(_cketh_minter_main_address);
        event_counter = 0;
        last_block_number = 0;
    }

    /**
     * @dev Return ckETH minter main address. 
     * @return address of ckETH minter main address. 
     */
    function getMinterAddress() public view returns (address) {
        return cketh_minter_main_address;
    }

    /**
     * @dev Emits the `ReceivedEth` event if the transfer succeeds.
     */
    function deposit(bytes32 _principal) public payable {
        if (block.number > last_block_number) {
            last_block_number = block.number;
            event_counter = 0;
        }
        require(event_counter < 0, "Maximum events per block reached");

        emit ReceivedEth(msg.sender, msg.value, _principal);
        cketh_minter_main_address.transfer(msg.value);
        event_counter++;
    }
} 