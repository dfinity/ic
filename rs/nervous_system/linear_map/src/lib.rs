use rust_decimal::Decimal;
use std::ops::Range;

/// A function that maps from one interval to another.
///
/// For example suppose you have a linear function that passes though two points
/// in the x-y plane: (6, 100) and (8, 50). Of course, you would want to know
/// the y value corresponding to any random x value. Here's how to do that:
///
/// ```
/// use ic_nervous_system_linear_map::LinearMap;
/// use rust_decimal::Decimal;
///
/// let example = LinearMap::new(6..8, 100..50);
/// assert_eq!(
///     example.apply(7),  // Since the input is half way between 6 and 8,
///     Decimal::from(75), // the output must be half way between 100 and 50.
/// );
/// ```
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LinearMap {
    from: Range<Decimal>,
    to: Range<Decimal>,
}

impl LinearMap {
    /// The ends of from must be different.
    pub fn new<N1, N2>(from: Range<N1>, to: Range<N2>) -> Self
    where
        Decimal: From<N1> + From<N2>,
    {
        let from = Decimal::from(from.start)..Decimal::from(from.end);
        let to = Decimal::from(to.start)..Decimal::from(to.end);

        // from must have nonzero length.
        assert!(from.end != from.start, "{from:#?}");
        Self { from, to }
    }

    /// Plugs x into self, and returns the result.
    ///
    /// It might seem strange that the output type is not the same as the input
    /// type, but if worked that way, information could be lost (due to
    /// truncation).
    pub fn apply<In>(&self, x: In) -> Decimal
    where
        Decimal: From<In>,
    {
        let x = Decimal::from(x);
        let Self { from, to } = &self;

        // t varies from 0 to 1 as x varies from from.start to from.end...
        // But if from.end == from.start, we set t to 1 to avoid division by
        // zero.
        let t = if from.end == from.start {
            Decimal::ONE
        } else {
            (x - from.start) / (from.end - from.start)
        };

        // Thus, the result varies from
        //   to.start * 1 + to.end * 0 = to.start
        // to
        //   to.start * (1 - 1) + to.end * 1 = to.end
        to.start * (Decimal::ONE - t) + to.end * t
    }
}
