//! Helpers for the deposit and withdrawal flows,
//! converting DOGE on Dogecoin into ckDOGE on ICP or the other way around.
//!
//! General design guidelines:
//! * 1 public method for each user interaction.
//! * Helper struct with only 1 or 2 public methods for auto-completion to become trivial.
//! * Prefix in method's name (e.g. `minter_` or `dogecoin_`) indicates the involved component.
pub mod deposit;
pub mod withdrawal;
