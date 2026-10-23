// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// Mimics USDT's non-standard ERC-20: `transfer`, `approve` and `transferFrom`
/// return no value, and `approve` requires resetting the allowance to zero first.
contract MockUSDT {
    string public constant name = "Mock Tether USD";
    string public constant symbol = "USDT";
    uint8 public constant decimals = 6;
    uint256 public immutable totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address initialHolder, uint256 initialSupply) {
        balanceOf[initialHolder] = initialSupply;
        totalSupply = initialSupply;
        emit Transfer(address(0), initialHolder, initialSupply);
    }

    function transfer(address to, uint256 value) external {
        require(balanceOf[msg.sender] >= value, "insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
    }

    function approve(address spender, uint256 value) external {
        require(value == 0 || allowance[msg.sender][spender] == 0, "reset allowance to 0 first");
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
    }

    function transferFrom(address from, address to, uint256 value) external {
        require(allowance[from][msg.sender] >= value, "insufficient allowance");
        require(balanceOf[from] >= value, "insufficient balance");
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
