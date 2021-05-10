use crate::displayer::{DisplayProxy, DisplayerOf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

/// `AmountOf<Unit>` provides a type-safe way to keep an amount of
/// some `Unit`.
///
///  E.g. the following code must not compile:
///
/// ```compile_fail
/// use phantom_newtype::AmountOf;
///
/// // These structs are just tags and have no semantic meaning.
/// enum Apples {}
/// enum Oranges {}
///
/// let trois_pommes = AmountOf::<Apples, u64>::from(3);
/// let three_oranges = AmountOf::<Oranges, u64>::from(3);
///
/// assert_eq!(trois_pommes, three_oranges)
/// ```
///
/// `AmountOf<Unit, Repr>` defines common boilerplate to make type-safe
/// amounts more convenient.  For example, you can compare amounts:
///
/// ```
/// use phantom_newtype::AmountOf;
///
/// enum MetricApple {}
/// type Apples = AmountOf<MetricApple, u64>;
///
/// assert!(Apples::from(3) < Apples::from(5));
/// assert_eq!(false, Apples::from(3) > Apples::from(5));
/// assert!(Apples::from(3) != Apples::from(5));
/// assert!(Apples::from(5) == Apples::from(5));
/// assert_eq!(false, Apples::from(5) != Apples::from(5));
///
/// assert_eq!(vec![Apples::from(3), Apples::from(5)].iter().max().unwrap(),
///            &Apples::from(5));
/// ```
///
/// You can do simple arithmetics with amounts:
///
/// ```
/// use phantom_newtype::AmountOf;
///
/// enum MetricApple {}
/// type Apples = AmountOf<MetricApple, u64>;
///
///
/// let mut x = Apples::from(5);
/// let y = Apples::from(3);
///
/// assert_eq!(x + y, Apples::from(8));
/// assert_eq!(x - y, Apples::from(2));
/// assert_eq!(x.increment(), Apples::from(6));
/// assert_eq!(x.decrement(), Apples::from(4));
///
/// // Variables are unmodified.
/// assert_eq!(x, Apples::from(5));
/// assert_eq!(y, Apples::from(3));
///
/// // But add assign and subtract assign will mutate the variable.
/// x += y;
/// assert_eq!(x, Apples::from(8));
/// x -= y;
/// assert_eq!(x, Apples::from(5));
/// x.inc_assign();
/// assert_eq!(x, Apples::from(6));
/// x.dec_assign();
/// assert_eq!(x, Apples::from(5));
///
/// assert_eq!(Apples::from(55), (1..=10_u64).map(Apples::from).sum());
/// ```
///
/// Multiplication of amounts is not supported: multiplying meters by
/// meters gives square meters. However, you can scale an amount by a
/// scalar; divide amounts; or divide amounts by scalars:
///
/// ```
/// use phantom_newtype::AmountOf;
///
/// enum Meter {}
///
/// type Meters = AmountOf<Meter, u64>;
///
/// let mut x = Meters::from(5);
///
/// assert_eq!(x * 3, Meters::from(15));
/// assert_eq!(1, x / x);
/// assert_eq!(3, (x * 3) / x);
/// // Note: integer division, because the representation is u64.
/// assert_eq!(Meters::from(1), x / 3);
///
/// // Variable is unmodified.
/// assert_eq!(x, Meters::from(5));
///
/// // But multiply assign and div assign will mutate it.
/// x *= 3;
/// assert_eq!(x, Meters::from(15));
/// x /= 5;
/// assert_eq!(x, Meters::from(3));
/// ```
///
/// Note that the unit is only available at compile time, thus using
/// `AmountOf` instead of `u64` doesn't incur any runtime penalty:
///
/// ```
/// use phantom_newtype::AmountOf;
///
/// enum Meter {}
///
/// type Meters = AmountOf<Meter, u64>;
///
/// let ms = Meters::from(10);
/// assert_eq!(std::mem::size_of_val(&ms), std::mem::size_of::<u64>());
/// ```
///
/// Amounts can be serialized and deserialized with `serde`. Serialized
/// forms of `Amount<Unit, Repr>` and `Repr` are identical.
///
/// ```
/// use phantom_newtype::AmountOf;
/// use serde::{Serialize, Deserialize};
/// use serde_json;
///
/// enum Meter {}
/// type Meters = AmountOf<Meter, u64>;
///
/// let repr: u64 = 10;
/// let m_10 = Meters::from(repr);
/// assert_eq!(serde_json::to_string(&m_10).unwrap(), serde_json::to_string(&repr).unwrap());
///
/// let copy: Meters = serde_json::from_str(&serde_json::to_string(&m_10).unwrap()).unwrap();
/// assert_eq!(copy, m_10);
/// ```
///
/// You can also declare constants of `AmountOf<Unit, Repr>` using `new`
/// function:
/// ```
/// use phantom_newtype::AmountOf;
/// enum Meter {}
/// type Distance = AmountOf<Meter, u64>;
/// const ASTRONOMICAL_UNIT: Distance = Distance::new(149_597_870_700);
///
/// assert!(ASTRONOMICAL_UNIT > Distance::from(0));
/// ```
pub struct AmountOf<Unit, Repr>(Repr, PhantomData<Unit>);

impl<Unit, Repr: Default> Default for AmountOf<Unit, Repr> {
    /// Returns the default amount if the value implements `Default`.
    ///
    /// ```
    /// use phantom_newtype::AmountOf;
    ///
    /// enum Apple {}
    ///
    /// #[derive(Default)]
    /// struct Bucket { apples: AmountOf::<Apple, u64> }
    ///
    /// let bucket = Bucket::default();
    /// assert_eq!(0, bucket.apples.get());
    /// ```
    fn default() -> Self {
        Self::new(Repr::default())
    }
}

impl<Unit, Repr: Copy> AmountOf<Unit, Repr> {
    /// Returns the wrapped value.
    ///
    /// ```
    /// use phantom_newtype::AmountOf;
    ///
    /// enum Apple {}
    ///
    /// let three_apples = AmountOf::<Apple, u64>::from(3);
    /// assert_eq!(9, (three_apples * 3).get());
    /// ```
    pub fn get(&self) -> Repr {
        self.0
    }
}

impl<Unit, Repr> AmountOf<Unit, Repr> {
    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants.
    pub const fn new(repr: Repr) -> AmountOf<Unit, Repr> {
        AmountOf(repr, PhantomData)
    }
}

impl<Unit: Default, Repr> AmountOf<Unit, Repr> {
    /// Provides a useful shortcut to access units of an amount if
    /// they implement the `Default` trait:
    ///
    /// ```
    /// use phantom_newtype::AmountOf;
    ///
    /// #[derive(Debug, Default)]
    /// struct Seconds {}
    /// let duration = AmountOf::<Seconds, u64>::from(5);
    ///
    /// assert_eq!("5 Seconds", format!("{} {:?}", duration, duration.unit()));
    /// ```
    pub fn unit(&self) -> Unit {
        Default::default()
    }
}

impl<Unit, Repr> AmountOf<Unit, Repr>
where
    Unit: DisplayerOf<AmountOf<Unit, Repr>>,
{
    /// `display` provides a machanism to implement a custom display
    /// for phantom types.
    ///
    /// ```
    /// use phantom_newtype::{AmountOf, DisplayerOf};
    /// use std::fmt;
    ///
    /// enum Cent {}
    /// type Money = AmountOf<Cent, u64>;
    ///
    /// impl DisplayerOf<Money> for Cent {
    ///   fn display(amount: &Money, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///     write!(f, "${}.{:02}", amount.get() / 100, amount.get() % 100)
    ///   }
    /// }
    ///
    /// assert_eq!(format!("{}", Money::from(1005).display()), "$10.05");
    /// ```
    pub fn display(&self) -> DisplayProxy<'_, Self, Unit> {
        DisplayProxy::new(self)
    }
}

impl<Unit, Repr> From<Repr> for AmountOf<Unit, Repr> {
    fn from(repr: Repr) -> Self {
        Self::new(repr)
    }
}

// Note that we only have to write the boilerplate trait
// implementation below because default implementations of traits put
// unnecessary restrictions on the type parameters. E.g. deriving
// `PartialEq<Wrapper<T>>` require `T` to implement `PartialEq`, which
// is not what we want: `T` is phantom in our case.

impl<Unit, Repr: Clone> Clone for AmountOf<Unit, Repr> {
    fn clone(&self) -> Self {
        AmountOf(self.0.clone(), PhantomData)
    }
}

impl<Unit, Repr: Copy> Copy for AmountOf<Unit, Repr> {}

impl<Unit, Repr: PartialEq> PartialEq for AmountOf<Unit, Repr> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Unit, Repr: Eq> Eq for AmountOf<Unit, Repr> {}

impl<Unit, Repr: PartialOrd> PartialOrd for AmountOf<Unit, Repr> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&rhs.0)
    }
}

impl<Unit, Repr: Ord> Ord for AmountOf<Unit, Repr> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.cmp(&rhs.0)
    }
}

impl<Unit, Repr: Hash> Hash for AmountOf<Unit, Repr> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<Unit, Repr> Add for AmountOf<Unit, Repr>
where
    Repr: Add<Output = Repr>,
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, PhantomData)
    }
}

impl<Unit, Repr> AddAssign for AmountOf<Unit, Repr>
where
    Repr: AddAssign,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

// TODO(MR-32): Implement `Step` trait once it's stabilised.
impl<Unit, Repr> AmountOf<Unit, Repr>
where
    Repr: Add<Output = Repr> + From<u8>,
{
    /// Returns the amount incremented by 1.
    pub fn increment(self) -> AmountOf<Unit, Repr> {
        Self(self.0 + Repr::from(1 as u8), PhantomData)
    }
}

impl<Unit, Repr> AmountOf<Unit, Repr>
where
    Repr: AddAssign + From<u8>,
{
    /// Increments the amount by 1.
    pub fn inc_assign(&mut self) {
        self.0 += Repr::from(1 as u8)
    }
}

impl<Unit, Repr> AmountOf<Unit, Repr>
where
    Repr: Sub<Output = Repr> + From<u8>,
{
    /// Returns the amount decremented by 1. Like regular subtraction, panics in
    /// debug mode if `Repr` is an unsigned integer type and the amount is zero.
    pub fn decrement(self) -> AmountOf<Unit, Repr> {
        Self(self.0 - Repr::from(1 as u8), PhantomData)
    }
}

impl<Unit, Repr> AmountOf<Unit, Repr>
where
    Repr: SubAssign + From<u8>,
{
    /// Decrements the amount by 1. Like regular subtraction, panics in debug
    /// mode if `Repr` is an unsigned integer type and the amount is zero.
    pub fn dec_assign(&mut self) {
        self.0 -= Repr::from(1 as u8)
    }
}

impl<Unit, Repr> SubAssign for AmountOf<Unit, Repr>
where
    Repr: SubAssign,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl<Unit, Repr> Sub for AmountOf<Unit, Repr>
where
    Repr: Sub<Output = Repr>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, PhantomData)
    }
}

impl<Unit, Repr> MulAssign<Repr> for AmountOf<Unit, Repr>
where
    Repr: MulAssign,
{
    fn mul_assign(&mut self, rhs: Repr) {
        self.0 *= rhs;
    }
}

impl<Unit, Repr> Mul<Repr> for AmountOf<Unit, Repr>
where
    Repr: Mul<Output = Repr>,
{
    type Output = Self;

    fn mul(self, rhs: Repr) -> Self {
        Self(self.0 * rhs, PhantomData)
    }
}

impl<Unit, Repr> Div<Self> for AmountOf<Unit, Repr>
where
    Repr: Div<Repr>,
{
    type Output = <Repr as Div>::Output;

    fn div(self, rhs: Self) -> Self::Output {
        self.0.div(rhs.0)
    }
}

impl<Unit, Repr> Div<Repr> for AmountOf<Unit, Repr>
where
    Repr: Div<Repr, Output = Repr>,
{
    type Output = Self;

    fn div(self, rhs: Repr) -> Self::Output {
        Self(self.0 / rhs, PhantomData)
    }
}

impl<Unit, Repr> DivAssign<Repr> for AmountOf<Unit, Repr>
where
    Repr: DivAssign,
{
    fn div_assign(&mut self, rhs: Repr) {
        self.0 /= rhs;
    }
}

impl<Unit, Repr> std::iter::Sum for AmountOf<Unit, Repr>
where
    Repr: std::iter::Sum,
{
    /// ```
    /// use phantom_newtype::AmountOf;
    ///
    /// enum MetricApple {}
    /// type Apples = AmountOf<MetricApple, u64>;
    ///
    /// let v = vec![Apples::from(1), Apples::from(2), Apples::from(3)];
    /// assert_eq!(v.into_iter().sum::<Apples>(), Apples::from(6));
    /// ```
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self::new(Repr::sum(iter.map(|a| a.0)))
    }
}

impl<'a, Unit, Repr> std::iter::Sum<&'a Self> for AmountOf<Unit, Repr>
where
    Repr: std::iter::Sum + Copy,
{
    /// ```
    /// use phantom_newtype::AmountOf;
    ///
    /// enum MetricApple {}
    /// type Apples = AmountOf<MetricApple, u64>;
    ///
    /// let v = vec![Apples::from(1), Apples::from(2), Apples::from(3)];
    /// assert_eq!(v.iter().sum::<Apples>(), Apples::from(6));
    /// ```
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        Self::new(Repr::sum(iter.map(|a| a.get())))
    }
}

impl<Unit, Repr> fmt::Debug for AmountOf<Unit, Repr>
where
    Repr: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<Unit, Repr> fmt::Display for AmountOf<Unit, Repr>
where
    Repr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Derived serde `impl Serialize` produces an extra `unit` value for
// phantom data, e.g. `AmountOf::<Meters>::from(10)` is serialized
// into json as `[10, null]` by default.
//
// We want serialization format of `Repr` and the `AmountOf` to match
// exactly, that's why we have to provide custom instances.
impl<Unit, Repr: Serialize> Serialize for AmountOf<Unit, Repr> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Unit, Repr> Deserialize<'de> for AmountOf<Unit, Repr>
where
    Repr: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Repr::deserialize(deserializer).map(AmountOf::<Unit, Repr>::new)
    }
}

/// ```
/// use phantom_newtype::AmountOf;
/// use candid::{Decode, Encode};
///
/// enum MetricApple {}
/// type Apples = AmountOf<MetricApple, u64>;
///
/// let amount = Apples::from(3);
/// let bytes = Encode!(&amount).unwrap();
/// let decoded = Decode!(&bytes, Apples).unwrap();
/// assert_eq!(amount, decoded);
/// ```
impl<Unit, Repr> candid::CandidType for AmountOf<Unit, Repr>
where
    Repr: candid::CandidType,
{
    fn id() -> candid::types::TypeId {
        Repr::id()
    }
    fn _ty() -> candid::types::Type {
        Repr::_ty()
    }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        self.0.idl_serialize(serializer)
    }
}

impl<Unit, Repr: slog::Value> slog::Value for AmountOf<Unit, Repr> {
    fn serialize(
        &self,
        record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.0.serialize(record, key, serializer)
    }
}
