use rust_decimal::{Decimal, RoundingStrategy};
use rust_decimal_macros::dec;

use super::{Atom, BinomialFormulaMember};

fn rescale(x: Decimal) -> Decimal {
    x.round_dp_with_strategy(8, RoundingStrategy::MidpointNearestEven)
}

#[test]
fn test_atom() {
    assert_eq!(Atom::new(dec!(-1), 254).eval().unwrap(), dec!(1));
    assert_eq!(Atom::new(dec!(-1), 255).eval().unwrap(), dec!(-1));
    assert_eq!(
        rescale(Atom::new(dec!(123.456), 0).eval().unwrap()),
        dec!(1)
    );
    assert_eq!(
        rescale(Atom::new(dec!(123.456), 1).eval().unwrap()),
        dec!(123.456)
    );
    assert_eq!(
        rescale(Atom::new(dec!(123.456), 2).eval().unwrap()),
        dec!(15241.383936)
    );
    assert_eq!(
        rescale(Atom::new(dec!(123.456), 3).eval().unwrap()),
        dec!(1881640.29520282)
    );
    assert_eq!(
        rescale(Atom::new(dec!(123.456), 4).eval().unwrap()),
        dec!(232299784.28455885)
    );
    assert!(Atom::new(dec!(123.456), 20).eval().is_err());
}

#[test]
fn test_member() {
    let a = Atom::new(dec!(123.456), 0);
    let b = Atom::new(dec!(123.456), 1);
    let c = Atom::new(dec!(123.456), 2);
    let d = Atom::new(dec!(123.456), 3);
    assert_eq!(
        rescale(
            BinomialFormulaMember::new(6, dec!(0), d.clone(), d.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
        dec!(0)
    );
    assert_eq!(
        rescale(
            BinomialFormulaMember::new(0, dec!(42), a.clone(), a.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
        dec!(42)
    );
    assert_eq!(
        rescale(
            BinomialFormulaMember::new(1, dec!(1), a.clone(), b.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
        dec!(123.456)
    );
    assert_eq!(
        rescale(
            BinomialFormulaMember::new(1, dec!(1), b.clone(), a.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
        dec!(123.456)
    );
    assert_eq!(
        rescale(
            BinomialFormulaMember::new(3, dec!(42), b.clone(), c.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
        rescale(
            BinomialFormulaMember::new(3, dec!(42), d.clone(), a.clone())
                .unwrap()
                .eval()
                .unwrap()
        ),
    );
}
