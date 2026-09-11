// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// Forwards ETH with Solidity's `transfer`, i.e. a 2'300-gas stipend — the
/// worst-case sender profile of a contract-batched CEX withdrawal.
contract StipendForwarder {
    function forward(address payable to) external payable {
        to.transfer(msg.value);
    }
}
