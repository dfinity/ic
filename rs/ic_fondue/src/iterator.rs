use rand::seq::SliceRandom;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use std::iter::FromIterator;

/// Implements an iterator over a permutation of a vector.
/// Every element is returned exactly once, but in unspecified order.
pub struct PermOf<'a, El> {
    elems: &'a [El],
    order: Vec<usize>,
}

impl<'a, El> PermOf<'a, El> {
    pub fn new<R: Rng>(v: &'a [El], rng: &mut R) -> Self {
        let mut order: Vec<usize> = (0..v.len()).collect();
        order.shuffle(rng);

        PermOf { elems: v, order }
    }
}

impl<'a, El> Iterator for PermOf<'a, El> {
    type Item = &'a El;

    fn next(&mut self) -> Option<Self::Item> {
        self.order.pop().map(|x| &self.elems[x])
    }
}

/// Implements an infinite iterator that keeps returning
/// random elements of a vector in unspecified order.
///
/// Please, do not call collect here.
pub struct InfStreamOf<'a, El> {
    elems: &'a [El],
    order: ChaCha8Rng,
}

impl<'a, El> InfStreamOf<'a, El> {
    pub fn new<R: Rng>(v: &'a [El], rng: &mut R) -> Self {
        let seed = rng.next_u64();

        InfStreamOf {
            elems: v,
            order: SeedableRng::seed_from_u64(seed),
        }
    }
}

impl<'a, El> Iterator for InfStreamOf<'a, El> {
    type Item = &'a El;

    fn next(&mut self) -> Option<Self::Item> {
        let x = self.order.gen_range(0..self.elems.len());
        Some(&self.elems[x])
    }

    fn collect<B>(self) -> B
    where
        B: FromIterator<Self::Item>,
    {
        panic!("Don't collect() on infinite iterator; consider using PermOf")
    }
}
