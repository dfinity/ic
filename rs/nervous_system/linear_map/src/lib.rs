use rust_decimal::Decimal;
use std::ops::Range;

// DO NOT MERGE - Migrate SNS rewards to this.
/// A function that maps from one interval to another.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LinearMap {
    from: Range<Decimal>,
    to: Range<Decimal>,
}

impl LinearMap {
    /// The ends of from must be different.
    pub fn new(from: Range<Decimal>, to: Range<Decimal>) -> Self {
        // from must have nonzero length.
        assert!(from.end != from.start, "{:#?}", from);
        Self { from, to }
    }

    pub fn apply(&self, x: Decimal) -> Decimal {
        let Self { from, to } = &self;

        // t varies from 0 to 1 as x varies from from.start to from.end...
        // But if from.end == from.start, we set t to 1 to avoid division by
        // zero.
        let t = if from.end == from.start {
            Decimal::from(1)
        } else {
            (x - from.start) / (from.end - from.start)
        };

        // Thus, the result varies from
        //   to.start * 1 + to.end * 0 = to.start
        // to
        //   to.start * (1 - 1) + to.end * 1 = to.end
        to.start * (Decimal::from(1) - t) + to.end * t
    }
}
