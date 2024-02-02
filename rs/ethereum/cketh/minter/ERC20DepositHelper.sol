// SPDX-License-Identifier: Apache-2.0

pragma solidity 0.8.18;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/**
 * @title A helper smart contract for ERC20 <-> ckERC20 conversion.
 * @notice This smart contract deposits incoming ERC-20 to the ckETH minter account and emits deposit events.
 */
contract CkErc20Deposit {
    address private immutable cketh_minter_main_address;
    event ReceivedErc20(address indexed erc20_contract_address, address indexed owner, uint256 amount, bytes32 indexed principal);

    /**
     * @dev Set cketh_minter_main_address.
     */
    constructor(address _cketh_minter_main_address) {
        cketh_minter_main_address = _cketh_minter_main_address;
    }

    /**
     * @dev Return ckETH minter main address.
     * @return address of ckETH minter main address.
     */
    function getMinterAddress() public view returns (address) {
        return cketh_minter_main_address;
    }

    /**
     * @dev Emits the `ReceivedErc20` event if the transfer succeeds.
     */
    function deposit(address erc20_address, uint256 amount, bytes32 principal) public {
        IERC20 erc20Token = IERC20(erc20_address);
        require(erc20Token.transferFrom(msg.sender, cketh_minter_main_address, amount), "ERC-20 transfer to minter failed");

        emit ReceivedErc20(erc20_address, msg.sender, amount, principal);
    }
}