/// Like [assert], but returns an error instead of panicking.
#[macro_export]
macro_rules! ensure {
    ($cond:expr_2021, $msg:expr_2021 $(, $args:expr_2021)* $(,)*) => {
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
    ($lhs:expr_2021, $rhs:expr_2021, $msg:expr_2021 $(, $args:expr_2021)* $(,)*) => {
        if $lhs != $rhs {
            return Err(format!("{} ({:?}) != {} ({:?}): {}",
                               std::stringify!($lhs), $lhs,
                               std::stringify!($rhs), $rhs,
                               format!($msg $(,$args)*)));
        }
    };
    ($lhs:expr_2021, $rhs:expr_2021 $(,)*) => {
        if $lhs != $rhs {
            return Err(format!("{} ({:?}) != {} ({:?})",
                               std::stringify!($lhs), $lhs,
                               std::stringify!($rhs), $rhs));
        }
    }
}
