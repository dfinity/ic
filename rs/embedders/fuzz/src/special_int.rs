use arbitrary::{Arbitrary, Result, Unstructured};
use num_traits::{Bounded, Signed};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SpecialInt<T>(pub T);

pub trait SpecialArbitrary: Sized + Bounded + Signed + Copy {
    fn special_values() -> &'static [Self];
}

impl SpecialArbitrary for i64 {
    fn special_values() -> &'static [Self] {
        &[Self::MIN, -1, 0, 1, Self::MAX, 4096, 65536]
    }
}

impl SpecialArbitrary for i32 {
    fn special_values() -> &'static [Self] {
        &[Self::MIN, -1, 0, 1, Self::MAX, 4096, 65536]
    }
}

impl<'a, T> Arbitrary<'a> for SpecialInt<T>
where
    T: SpecialArbitrary + Arbitrary<'a> + 'static,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // 50% chance to return a special value
        if u.ratio(1, 2)? {
            let idx = u.int_in_range(0..=T::special_values().len() - 1)?;
            Ok(SpecialInt(T::special_values()[idx]))
        } else {
            // Otherwise, generate a normal arbitrary number
            Ok(SpecialInt(T::arbitrary(u)?))
        }
    }
}
