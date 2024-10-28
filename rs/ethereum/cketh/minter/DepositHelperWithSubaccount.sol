// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {SafeERC20, IERC20} from "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title A helper smart contract for ETH <-> ckETH and ERC20 <-> ckERC20 conversions.
 * @notice This smart contract deposits incoming funds to the ckETH minter account and emits deposit events.
 */
contract CkDeposit {
    using SafeERC20 for IERC20;

    address payable private immutable minterAddress;

    event ReceivedEth(
        address indexed from,
        uint256 value,
        bytes32 indexed principal,
        bytes32 subaccount
    );

    event ReceivedErc20(
        address indexed erc20ContractAddress,
        address indexed owner,
        uint256 amount,
        bytes32 indexed principal,
        bytes32 subaccount
    );

    /**
     * @dev Set cketh_minter_main_address.
     */
    constructor(address _minterAddress) {
        minterAddress = payable(_minterAddress);
    }

    /**
     * @dev Return ckETH minter main address.
     * @return address of ckETH minter main address.
     */
    function getMinterAddress() public view returns (address) {
        return minterAddress;
    }

    /**
     * @dev Emits the `ReceivedEth` event if the transfer succeeds.
     */
    function depositEth(bytes32 principal, bytes32 subaccount) public payable {
        emit ReceivedEth(msg.sender, msg.value, principal, subaccount);
        minterAddress.transfer(msg.value);
    }

    /**
     * @dev Emits the `ReceivedErc20` event if the transfer succeeds.
     */
    function depositErc20(
        address erc20Address,
        uint256 amount,
        bytes32 principal,
        bytes32 subaccount
    ) public {
        IERC20 erc20Token = IERC20(erc20Address);
        erc20Token.safeTransferFrom(
            msg.sender,
            minterAddress,
            amount
        );

        emit ReceivedErc20(
            erc20Address,
            msg.sender,
            amount,
            principal,
            subaccount
        );
    }
}
