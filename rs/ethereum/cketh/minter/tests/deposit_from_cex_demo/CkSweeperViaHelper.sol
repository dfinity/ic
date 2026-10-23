// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface ICkDeposit {
    function depositErc20(address erc20Address, uint256 amount, bytes32 principal, bytes32 subaccount) external;
}

interface IErc20Balance {
    function balanceOf(address account) external view returns (uint256);
}

/// EIP-7702 delegate variant that sweeps by calling the existing ckETH helper
/// contract (CkDeposit, see minter/DepositHelperWithSubaccount.sol), so that
/// the sweep emits the canonical ReceivedEthOrErc20 event consumed by the
/// minter's unchanged deposit pipeline.
/// The IC principal/subaccount are caller-supplied, so sweeping MUST NOT be
/// permissionless (anyone could credit deposits to their own principal):
/// only the minter, directly or through the batch entry point of the deployed
/// instance (SELF), may sweep.
contract CkSweeperViaHelper {
    address private immutable MINTER;
    address private immutable HELPER;
    address private immutable SELF;

    constructor(address minter, address helper) {
        MINTER = minter;
        HELPER = helper;
        SELF = address(this);
    }

    function sweepErc20(address[] calldata tokens, bytes32 principal, bytes32 subaccount) external {
        require(msg.sender == MINTER || msg.sender == SELF, "caller is not the minter");
        for (uint256 i = 0; i < tokens.length; ++i) {
            uint256 balance = IErc20Balance(tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                _safeApprove(tokens[i], HELPER, balance);
                ICkDeposit(HELPER).depositErc20(tokens[i], balance, principal, subaccount);
            }
        }
    }

    /// Batch entry point on the deployed instance: sweeps many delegated
    /// deposit EOAs in a single transaction, each towards its own IC account.
    function sweepErc20Batch(
        address[] calldata depositAddresses,
        bytes32[] calldata principals,
        bytes32[] calldata subaccounts,
        address[] calldata tokens
    ) external {
        require(msg.sender == MINTER, "caller is not the minter");
        require(
            depositAddresses.length == principals.length && principals.length == subaccounts.length,
            "length mismatch"
        );
        for (uint256 i = 0; i < depositAddresses.length; ++i) {
            CkSweeperViaHelper(depositAddresses[i]).sweepErc20(tokens, principals[i], subaccounts[i]);
        }
    }

    /// Tolerates non-standard ERC-20s such as USDT whose approve returns no value.
    function _safeApprove(address token, address spender, uint256 value) private {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("approve(address,uint256)", spender, value));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "approve failed");
    }
}
