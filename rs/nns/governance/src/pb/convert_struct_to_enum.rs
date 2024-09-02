//! This (sub)*module contains lots of implementations of conversions that
//! "upgrade" a struct into an enum. For example,
//!
//!     impl From<SetVisibility> for Operation {
//!         fn from(src: SetVisibility) -> Operation {
//!             Operation::SetVisibility(src)
//!         }
//!     }
//!
//! (Almost all of the code in this (sub)*module is completely mechanical.
//! Perhaps, with the right Prost incantation, this can be automated away.)

mod manage_neuron;
