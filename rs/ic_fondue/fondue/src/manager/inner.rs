use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    panic::{RefUnwindSafe, UnwindSafe},
};

use crate::log::Logger;

pub trait HasHandle {
    type Handle: UnwindSafe + RefUnwindSafe + Clone;

    fn handle(&self) -> Self::Handle;
}

pub trait MaybeHasHandle<H: UnwindSafe + RefUnwindSafe + Clone> {
    fn request_handle(&self) -> Option<Box<dyn HasHandle<Handle = H>>>;
}

impl<H: UnwindSafe + RefUnwindSafe + Clone> MaybeHasHandle<H> for () {
    fn request_handle(&self) -> Option<Box<dyn HasHandle<Handle = H>>> {
        None
    }
}

/// Manages the environment resources.
pub trait Manager: HasHandle + UnwindSafe + RefUnwindSafe + Send + Clone {
    type Event: Send;
    /// An environment configuration must be clonable and Summarize'able.
    /// Often, a `#[derive(Hash)]` works as a summary. Nevertheless, we use the
    /// summary of the configuration for a pot's derived name, creating
    /// opportunities for further sharing and for identifying what is running
    /// where.
    type EnvConfig: Clone + Summarize;
    /// Additionally, users might want to speficy some manager configuration to
    /// be passed at startup.
    type ManConfig: MaybeHasHandle<Self::Handle> + Clone;

    /// Starts a manager with the provided configuration.
    fn start(
        pot_name: String,
        settings: Self::ManConfig,
        cfg: Self::EnvConfig,
        logger: &Logger,
    ) -> Self;

    /// Waits until a manager receives a signal or returns None if the manager
    /// gets dropped.
    fn wait_for_signal(&self) -> Option<i32>;
}

pub trait Summarize {
    /// A [crate::pot::Pot] has a derived name computed from its configuration
    /// and test names. This name is computed through this summarize function.
    /// The easiest way to use this is to derive `Hash` for whatever
    /// [Manager::EnvConfig] type you chose. In that case, the default instance
    /// will be used.
    fn summarize(&self) -> String;
}

impl<T: Hash> Summarize for T {
    fn summarize(&self) -> String {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        let my_hash = s.finish();
        format!("{:x}", my_hash)[0..8].to_string()
    }
}
