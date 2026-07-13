// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface ICkDeposit {
    function depositErc20(address erc20Address, uint256 amount, bytes32 principal, bytes32 subaccount) external;
}

interface IErc20Balance {
    function balanceOf(address account) external view returns (uint256);
}

/// One deposit address to sweep, with its attested IC account and the (r, s, v)
/// attestation signature. Grouping the parallel arrays into a struct array keeps
/// the batch loop within the EVM stack limit.
struct SweepItem {
    address deposit;
    bytes32 principal;
    bytes32 subaccount;
    bytes32 r;
    bytes32 s;
    uint8 v;
}

/// EIP-7702 delegate variant with *permissionless* sweeping (the proposed
/// one-time self-attestation design, see docs/deposit_from_cex.md). Anyone may
/// submit a sweep, but each sweep must carry an attestation: a secp256k1
/// signature by the deposit address' own key (produced by the minter via
/// threshold ECDSA) over a domain-separated digest binding the address to its IC
/// account. Running as a delegate, `address(this)` is the deposit EOA, so the
/// digest recovers to it only for the signature by that address' key — a caller
/// supplying their own principal fails the check. The attestation is passed as
/// its (r, s, v) components.
contract CkSweeperAttested {
    address private immutable HELPER;

    constructor(address helper) {
        HELPER = helper;
    }

    /// The attestation digest: keccak256 over a fixed-length, domain-separated
    /// preimage. The ASCII prefix (first byte 0x63) cannot collide with typed
    /// transactions (0x00-0x04), EIP-7702 authorizations (0x05), EIP-191/712
    /// (0x19) or legacy-transaction RLP (>= 0xc0).
    function _attestationDigest(bytes32 principal, bytes32 subaccount) private view returns (bytes32) {
        return keccak256(abi.encodePacked("ck-deposit-owner", block.chainid, HELPER, principal, subaccount));
    }

    function sweepErc20(
        address[] calldata tokens,
        bytes32 principal,
        bytes32 subaccount,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        require(
            ecrecover(_attestationDigest(principal, subaccount), v, r, s) == address(this),
            "invalid attestation"
        );
        for (uint256 i = 0; i < tokens.length; ++i) {
            uint256 balance = IErc20Balance(tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                _safeApprove(tokens[i], HELPER, balance);
                ICkDeposit(HELPER).depositErc20(tokens[i], balance, principal, subaccount);
            }
        }
    }

    /// Permissionless batch entry point: sweeps many delegated deposit EOAs in a
    /// single transaction, each with its own attestation.
    function sweepErc20Batch(SweepItem[] calldata items, address[] calldata tokens) external {
        for (uint256 i = 0; i < items.length; ++i) {
            SweepItem calldata item = items[i];
            CkSweeperAttested(item.deposit).sweepErc20(
                tokens, item.principal, item.subaccount, item.r, item.s, item.v
            );
        }
    }

    /// Tolerates non-standard ERC-20s such as USDT whose approve returns no value.
    function _safeApprove(address token, address spender, uint256 value) private {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("approve(address,uint256)", spender, value));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "approve failed");
    }
}
