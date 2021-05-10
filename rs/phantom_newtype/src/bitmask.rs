use crate::displayer::{DisplayProxy, DisplayerOf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// `BitMask<Unit>` provides a type-safe way to work with bitmasks.
///
///  E.g. the following code must not compile:
///
/// ```compile_fail
/// use phantom_newtype::BitMask;
///
/// // These structs are just markers and have no semantic meaning.
/// enum Prot {}
/// enum Map {}
///
/// type ProtMask = BitMask<Prot, u32>;
/// type MapMask = BitMask<Map, u32>;
///
/// const PROT_NONE: ProtMask = ProtMask::new(0);
/// const MAP_ANON: MapMask = MapMask::new(0);
///
/// assert_eq!(0, (PROT_NONE | MAP_ANON).get())
/// ```
///
/// `BitMask` provides all the typical bitwise operations you'd
/// expect:
///
/// ```
/// use phantom_newtype::BitMask;
///
/// enum Prot {}
/// type ProtMask = BitMask<Prot, u32>;
///
/// const PROT_R: ProtMask = ProtMask::new(1);
/// const PROT_W: ProtMask = ProtMask::new(2);
///
/// assert_eq!(ProtMask::new(3), PROT_R | PROT_W);
/// assert_eq!(ProtMask::new(0), PROT_R & PROT_W);
/// assert_eq!(ProtMask::new(3), PROT_R ^ PROT_W);
///
/// let mut mask = ProtMask::new(0);
/// mask |= PROT_R;
/// assert_eq!(mask, PROT_R);
///
/// mask |= PROT_W;
/// assert_eq!(mask, PROT_W | PROT_R);
///
/// assert!(mask.is_set(PROT_R));
/// assert!(mask.is_set(PROT_W));
/// ```
///
/// Note that the unit is only available at compile time, thus using
/// `BitMask` instead of `u64` doesn't incur any runtime penalty:
///
/// ```
/// use phantom_newtype::BitMask;
///
/// enum Prot {}
///
/// let prot_none = BitMask::<Prot, u64>::from(0);
/// assert_eq!(std::mem::size_of_val(&prot_none), std::mem::size_of::<u64>());
/// ```
///
/// Amounts can be serialized and deserialized with `serde`. Serialized
/// forms of `BitMask<Unit, Repr>` and `Repr` are identical.
///
/// ```
/// use phantom_newtype::BitMask;
/// use serde::{Serialize, Deserialize};
/// use serde_json;
/// enum Prot {}
/// type ProtMask = BitMask<Prot, u64>;
///
/// let repr: u64 = 10;
/// let bm_10 = ProtMask::from(repr);
/// assert_eq!(serde_json::to_string(&bm_10).unwrap(), serde_json::to_string(&repr).unwrap());
///
/// let copy: ProtMask = serde_json::from_str(&serde_json::to_string(&bm_10).unwrap()).unwrap();
/// assert_eq!(copy, bm_10);
/// ```
///
/// You can also declare constants of `BitMask<Unit, Repr>` using `new`
/// function:
///
/// ```
/// use phantom_newtype::BitMask;
/// enum Prot {}
/// type ProtMask = BitMask<Prot, u64>;
/// const PROT_NONE: ProtMask = ProtMask::new(0);
/// ```
pub struct BitMask<Unit, Repr>(Repr, PhantomData<Unit>);

impl<Unit, Repr: Copy> BitMask<Unit, Repr> {
    /// Returns the wrapped value.
    ///
    /// ```
    /// use phantom_newtype::BitMask;
    ///
    /// enum Prot {}
    ///
    /// let prot_read = BitMask::<Prot, u64>::from(1 << 1);
    /// assert_eq!(2, prot_read.get());
    /// ```
    pub fn get(&self) -> Repr {
        self.0
    }
}

impl<Unit, Repr> BitMask<Unit, Repr> {
    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants.
    pub const fn new(repr: Repr) -> BitMask<Unit, Repr> {
        BitMask(repr, PhantomData)
    }
}

impl<Unit, Repr> BitMask<Unit, Repr>
where
    Repr: Copy + PartialEq + BitOr<Repr, Output = Repr>,
{
    pub fn is_set(self, mask: Self) -> bool {
        (self | mask) == self
    }
}

impl<Unit, Repr> BitMask<Unit, Repr>
where
    Unit: DisplayerOf<BitMask<Unit, Repr>>,
{
    /// `display` provides a machanism to implement a custom display
    /// for phantom types.
    ///
    /// ```
    /// use phantom_newtype::{BitMask, DisplayerOf};
    /// use std::fmt;
    ///
    /// enum Prot {}
    /// type ProtMask = BitMask<Prot, u64>;
    /// const PROT_READ: ProtMask = ProtMask::new(1);
    /// const PROT_WRITE: ProtMask = ProtMask::new(1 << 1);
    /// const PROT_EXEC: ProtMask = ProtMask::new(1 << 2);
    ///
    /// fn ternary(mask: ProtMask, ok: &'static str, nok: &'static str) -> &'static str {
    ///   if mask != ProtMask::new(0) {
    ///     ok
    ///   } else {
    ///     nok
    ///   }
    /// }
    ///
    /// impl DisplayerOf<ProtMask> for Prot {
    ///   fn display(mask: &ProtMask, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///     write!(f, "{}{}{}",
    ///            ternary(*mask & PROT_READ, "r", "-"),
    ///            ternary(*mask & PROT_WRITE, "w", "-"),
    ///            ternary(*mask & PROT_EXEC, "x", "-"))
    ///   }
    /// }
    ///
    /// assert_eq!(format!("{}", (PROT_READ | PROT_EXEC).display()), "r-x");
    /// ```
    pub fn display(&self) -> DisplayProxy<'_, Self, Unit> {
        DisplayProxy::new(self)
    }
}

impl<Unit, Repr: Copy> From<Repr> for BitMask<Unit, Repr> {
    fn from(repr: Repr) -> Self {
        Self::new(repr)
    }
}

impl<Unit, Repr: Copy> Clone for BitMask<Unit, Repr> {
    fn clone(&self) -> Self {
        BitMask(self.0, PhantomData)
    }
}

impl<Unit, Repr: Copy> Copy for BitMask<Unit, Repr> {}

impl<Unit, Repr: PartialEq> PartialEq for BitMask<Unit, Repr> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Unit, Repr: Eq> Eq for BitMask<Unit, Repr> {}

impl<Unit, Repr: Hash> Hash for BitMask<Unit, Repr> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<Unit, Repr> BitAndAssign for BitMask<Unit, Repr>
where
    Repr: BitAndAssign + Copy,
{
    fn bitand_assign(&mut self, rhs: Self) {
        self.get().bitand_assign(rhs.get())
    }
}

impl<Unit, Repr> BitAnd for BitMask<Unit, Repr>
where
    Repr: BitAnd + Copy,
{
    type Output = BitMask<Unit, <Repr as BitAnd>::Output>;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::Output::new(self.get().bitand(rhs.get()))
    }
}

impl<Unit, Repr> BitOrAssign for BitMask<Unit, Repr>
where
    Repr: BitOrAssign + Copy,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.0.bitor_assign(rhs.get())
    }
}

impl<Unit, Repr> BitOr for BitMask<Unit, Repr>
where
    Repr: BitOr + Copy,
{
    type Output = BitMask<Unit, <Repr as BitOr>::Output>;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Output::new(self.get().bitor(rhs.get()))
    }
}

impl<Unit, Repr> BitXorAssign for BitMask<Unit, Repr>
where
    Repr: BitXorAssign + Copy,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.get())
    }
}

impl<Unit, Repr> BitXor for BitMask<Unit, Repr>
where
    Repr: BitXor + Copy,
{
    type Output = BitMask<Unit, <Repr as BitXor>::Output>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output::new(self.get().bitxor(rhs.get()))
    }
}

impl<Unit, Repr> Not for BitMask<Unit, Repr>
where
    Repr: Not + Copy,
{
    type Output = BitMask<Unit, <Repr as Not>::Output>;

    fn not(self) -> Self::Output {
        Self::Output::new(self.get().not())
    }
}

impl<Unit, Repr> fmt::Debug for BitMask<Unit, Repr>
where
    Repr: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<Unit, Repr> fmt::Display for BitMask<Unit, Repr>
where
    Repr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<Unit, Repr: Serialize> Serialize for BitMask<Unit, Repr> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Unit, Repr> Deserialize<'de> for BitMask<Unit, Repr>
where
    Repr: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Repr::deserialize(deserializer).map(BitMask::<Unit, Repr>::new)
    }
}
