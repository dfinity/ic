# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-05-31: Proposal 136797

http://dashboard.internetcomputer.org/proposal/136797

## Changed

- Use the mint_cycles128 system API, so larger amounts of cycles can now be minted.


# 2025-02-07: Proposal 135205

http://dashboard.internetcomputer.org/proposal/135205

## Added

* Automatically refund when the memo in an incoming ICP transfer is not one of
  the special values that indicate the purpose of the transfer (e.g. to create a
  new canister). This was originally proposed without objection in [the forum].

[the forum]: https://forum.dfinity.org/t/extend-cycles-minting-canister-functionality/37749/2


END
