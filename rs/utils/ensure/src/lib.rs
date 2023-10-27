/// Like [assert], but returns an error instead of panicking.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $msg:expr $(, $args:expr)* $(,)*) => {
        if !$cond {
            return Err(format!("Condition {} is false: {}",
                               std::stringify!($cond),
                               format!($msg $(,$args)*)));
        }
    }
}

/// Like [assert_eq], but returns an error instead of panicking.
#[macro_export]
macro_rules! ensure_eq {
    ($lhs:expr, $rhs:expr, $msg:expr $(, $args:expr)* $(,)*) => {
        if $lhs != $rhs {
            return Err(format!("{} ({:?}) != {} ({:?}): {}",
                               std::stringify!($lhs), $lhs,
                               std::stringify!($rhs), $rhs,
                               format!($msg $(,$args)*)));
        }
    };
    ($lhs:expr, $rhs:expr $(,)*) => {
        if $lhs != $rhs {
            return Err(format!("{} ({:?}) != {} ({:?})",
                               std::stringify!($lhs), $lhs,
                               std::stringify!($rhs), $rhs));
        }
    }
}
