use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub mod buffered_reader;
pub mod log;
pub mod manager;
pub mod mcond;
pub mod mvar;
pub mod pot;
pub mod util;

/// If this functino succeeds, sending two SIGINT (Ctrl+C in most terminals)
/// will terminate the process. This function should often be the first function
/// called from your main file, especially if you are registering some sort of
/// signal handling within your manager's definition.
///
/// If you use [crate::manager::process_pool::ProcessPool], it is highly
/// advisable you also call `register_double_ctrlc_kill` since the [ProcessPool]
/// installs its own signal handler and, hence, if something goes wrong over
/// there, the signals can be ignored.
pub fn register_double_ctrlc_kill() -> std::io::Result<()> {
    // Make sure double CTRL+C and similar kills
    let term_now = Arc::new(AtomicBool::new(false));
    for sig in TERM_SIGNALS {
        // When terminated by a second term signal, exit with exit code 1.
        // This will do nothing the first time (because term_now is false).
        flag::register_conditional_shutdown(*sig, 1, Arc::clone(&term_now))?;
        // But this will "arm" the above for the second time, by setting it to true.
        // The order of registering these is important, if you put this one first, it
        // will first arm and then terminate ‒ all in the first round.
        flag::register(*sig, Arc::clone(&term_now))?;
    }

    Ok(())
}

pub mod mio {
    //! Here we define some mio-helpers, namely, a simple way to use
    //! `mio::Tokens` for processes that have multiple input sources.
    //! The trick consists in encoding the input source and the pid
    //! in the same usize.
    //!
    //! We currently use [InputSource] below both in [crate::pot::execution]
    //! and in [crate::manager::process_pool].

    use mio::Token;
    use nix::unistd::Pid;
    use std::fmt;

    /// Dedicated token used for signal handling that is guaranteed never to
    /// overlap with anthing else. That is, will never be returned by
    /// [make_token] since the process id is always non-zero.
    pub const SIGNAL_TOKEN: Token = Token(0);

    /// Whenever mio::poll is awoken, it associates a token with
    /// which the source awoke. This token often consists of a process id but
    /// we'll also add information about whether to read stdout, stderr or
    /// some additional information source in case there are other sources
    /// we want mio to wait on.
    #[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, serde::Serialize)]
    pub enum InputSource {
        Stdout,
        Stderr,

        /// For an example of usage please see [crate::manager::process_pool].
        /// There, when the chosen `Cfg` returns a non empty vector from
        /// [crate::manager::process_pool::ManagedProcessCfg::
        /// auxiliary_info_source], the process pool will monitor the
        /// given file descriptors and tag it with [InputSource::Auxsrc]
        /// with their according index in the vector.
        ///
        /// WARNING: We assume the argument to `Auxsrc` will never need
        /// more than [MAX_AUXSRC_BITS] to represent.
        Auxsrc(usize),
    }

    impl fmt::Display for InputSource {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                InputSource::Stdout => write!(f, "stdout"),
                InputSource::Stderr => write!(f, "stderr"),
                InputSource::Auxsrc(n) => write!(f, "aux:{:?}", n),
            }
        }
    }

    /// This specifies how many bits of a [mio::Token] we reserve for
    /// the index of the auxsrc, yet, the maximum available index for
    /// usage is [MAX_AUXSRC_IX].
    pub const MAX_AUXSRC_BITS: usize = 4;

    /// Because we also have to encode stderr and stdout within
    /// [MAX_AUXSRC_BITS], the user only gets to use two less indexes
    /// than what you would expect, hence the "minus 3".
    pub const MAX_AUXSRC_IX: usize = (1 << MAX_AUXSRC_BITS) - 3;

    impl InputSource {
        pub fn enumerate() -> impl Iterator<Item = Self> {
            let mut v = vec![InputSource::Stdout, InputSource::Stderr];

            for i in 0..MAX_AUXSRC_IX {
                v.push(InputSource::Auxsrc(i));
            }

            v.into_iter()
        }

        pub fn to_usize(&self) -> usize {
            match self {
                InputSource::Stdout => 0,
                InputSource::Stderr => 1,
                InputSource::Auxsrc(n) => 2 + n,
            }
        }

        pub fn from_usize(x: usize) -> Self {
            // Because we account for stdout and stderr, the maximum allowed x is
            // two plus the maximum allowed auxsrc index.
            if x > MAX_AUXSRC_IX + 2 {
                panic!("Can't convert usize to InputSource: index too large");
            }

            match x {
                0 => InputSource::Stdout,
                1 => InputSource::Stderr,
                _ => InputSource::Auxsrc(x - 2),
            }
        }
    }

    pub fn make_token(pid: Pid, source: InputSource) -> Token {
        Token((pid.as_raw() as usize) << MAX_AUXSRC_BITS | source.to_usize())
    }

    pub fn split_token(token: Token) -> (Pid, InputSource) {
        // Produces a usize where the leftmost MAX_AUXSRC_BITS bits are set to 1
        // and the rest are set to 0; this makes it easy to extract the
        // "source" portion of the token.
        const MASK: usize = !(usize::MAX << MAX_AUXSRC_BITS);
        let raw_src = token.0 & MASK;
        let raw_pid = token.0 >> MAX_AUXSRC_BITS;

        (
            Pid::from_raw(raw_pid as i32),
            InputSource::from_usize(raw_src),
        )
    }
}
