use std::fmt;

pub enum BoolExpr {
    And(Box<BoolExpr>, Box<BoolExpr>),
    Or(Box<BoolExpr>, Box<BoolExpr>),
    Not(Box<BoolExpr>),
    Single(String),
    True,
    False,
}

impl BoolExpr {
    pub fn ors(iter: impl IntoIterator<Item = Self>) -> Self {
        use self::BoolExpr::*;

        let mut iter = iter.into_iter();

        let a = match iter.next() {
            None => return False,
            Some(a) => a,
        };

        iter.fold(a, |a, b| a.or(b))
    }

    pub fn ands(iter: impl IntoIterator<Item = Self>) -> Self {
        use self::BoolExpr::*;

        let mut iter = iter.into_iter();

        let a = match iter.next() {
            None => return False,
            Some(a) => a,
        };

        iter.fold(a, |a, b| a.and(b))
    }

    pub fn and(self, b: Self) -> Self {
        BoolExpr::And(Box::new(self), Box::new(b))
    }

    pub fn or(self, b: Self) -> Self {
        BoolExpr::Or(Box::new(self), Box::new(b))
    }

    pub fn not(self) -> Self {
        BoolExpr::Not(Box::new(self))
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            BoolExpr::True => Some(true),
            BoolExpr::False => Some(false),
            _ => None,
        }
    }

    pub fn simplify(self) -> Self {
        use self::BoolExpr::*;

        match self {
            And(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (a.as_bool(), b.as_bool()) {
                    (Some(true), _) => b,
                    (Some(false), _) => False,
                    (_, Some(true)) => a,
                    (_, Some(false)) => False,
                    _ => a.and(b),
                }
            }
            Or(a, b) => {
                let a = a.simplify();
                let b = b.simplify();
                match (a.as_bool(), b.as_bool()) {
                    (Some(true), _) => True,
                    (Some(false), _) => b,
                    (_, Some(true)) => True,
                    (_, Some(false)) => a,
                    _ => a.or(b),
                }
            }
            Not(a) => {
                let a = a.simplify();
                match a {
                    False => True,
                    True => False,
                    a => a.not(),
                }
            }
            a => a,
        }
    }
}

#[derive(Eq, PartialEq)]
enum Parent {
    PAnd,
    POr,
    PNot,
    PRoot,
}

impl BoolExpr {
    pub fn to_nix(&self) -> impl '_ + fmt::Display {
        DisplayFn(move |f: &mut fmt::Formatter| self.write_nix(f, Parent::PRoot))
    }

    fn write_nix(&self, f: &mut fmt::Formatter, parent: Parent) -> fmt::Result {
        use self::BoolExpr::*;
        use self::Parent::*;

        Ok(match self {
            And(a, b) => {
                parenthesize_if(parent == PNot, f, |f| {
                    a.write_nix(f, PAnd)?;
                    write!(f, " && ")?;
                    b.write_nix(f, PAnd)?;
                    Ok(())
                })?;
            }
            Or(a, b) => {
                parenthesize_if(parent == PAnd || parent == PNot, f, |f| {
                    a.write_nix(f, POr)?;
                    write!(f, " || ")?;
                    b.write_nix(f, POr)?;
                    Ok(())
                })?;
            }
            Not(a) => {
                write!(f, "!")?;
                a.write_nix(f, PNot)?;
            }
            Single(a) => {
                let a = a.to_string();
                parenthesize_if(parent == PNot && !is_valid_ident(&a), f, |f| {
                    write!(f, "{}", a)
                })?;
            }
            True => write!(f, "true")?,
            False => write!(f, "false")?,
        })
    }
}

fn parenthesize_if<F>(cond: bool, f: &mut fmt::Formatter, inner: F) -> fmt::Result
where
    F: FnOnce(&mut fmt::Formatter) -> fmt::Result,
{
    if cond {
        write!(f, "(")?;
    }
    inner(f)?;
    if cond {
        write!(f, ")")?;
    }
    Ok(())
}

fn is_valid_ident(id: &str) -> bool {
    let mut chars = id.chars();

    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || "_'-.".contains(c))
}

#[derive(Clone)]
struct DisplayFn<F>(pub F);

impl<F> fmt::Display for DisplayFn<F>
where
    F: Fn(&mut fmt::Formatter) -> fmt::Result,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self.0)(f)
    }
}
