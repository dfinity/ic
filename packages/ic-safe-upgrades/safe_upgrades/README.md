# IC Safe Upgrades

A library for safely upgrading canisters (from other canisters) on the Internet Computer.

The upgrades are done through bounded-wait calls, ensuring that the calling canister (initiating the upgrade) doesn't get prevented from upgrading itself because it's waiting on an inter-canister call. The library currently assumes that the calling canister is the only controller of the target canister being upgraded, and in particular that the calling canister ensures that there is only one upgrade of the target concurrently in progress.

For usage examples, see the [tests](https://github.com/oggy-dfin/ic_call_utils/tree/master/safe_upgrade/tests).
