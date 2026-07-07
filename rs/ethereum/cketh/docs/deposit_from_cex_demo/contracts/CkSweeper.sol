// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IERC20View {
    function balanceOf(address account) external view returns (uint256);
}

/// EIP-7702 delegate for minter-controlled deposit addresses.
/// Stateless on purpose: a 7702 delegate executes in the EOA's storage context.
/// Sweep functions are callable by anyone since funds can only move to MINTER.
contract CkSweeper {
    address payable private immutable MINTER;

    constructor(address minter) {
        MINTER = payable(minter);
    }

    function sweepErc20(address[] calldata tokens) external {
        for (uint256 i = 0; i < tokens.length; ++i) {
            uint256 balance = IERC20View(tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                _safeTransfer(tokens[i], balance);
            }
        }
    }

    /// Batch entry point: the deployed CkSweeper instance doubles as the
    /// batcher, sweeping many delegated deposit EOAs in a single transaction.
    function sweepErc20Batch(address[] calldata depositAddresses, address[] calldata tokens) external {
        for (uint256 i = 0; i < depositAddresses.length; ++i) {
            CkSweeper(depositAddresses[i]).sweepErc20(tokens);
        }
    }

    function sweepEth() external {
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool ok,) = MINTER.call{value: balance}("");
            require(ok, "ETH sweep failed");
        }
    }

    /// Tolerates non-standard ERC-20s such as USDT whose transfer returns no value.
    function _safeTransfer(address token, uint256 value) private {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", MINTER, value));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "token sweep failed");
    }
}
