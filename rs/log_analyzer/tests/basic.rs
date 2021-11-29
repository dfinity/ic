use log_analyzer::*;

#[test]
fn basic_functionality() {
    let consts: Vec<i32> = vec![1, 2, 3];
    assert_eq!(
        Answer::Success,
        run(
            and(eq(1), next(and(eq(2), next(eq(3))))),
            consts.into_iter()
        )
    );
}

#[test]
fn basic_fibs() {
    let consts: Vec<i32> = vec![1, 1, 2, 3, 5, 8, 13, 21];
    assert_eq!(
        Answer::Success,
        run(
            always(examine(|x1: &i32| next(examine({
                let x1 = *x1;
                move |x2: &i32| next(eq(x1 + *x2))
            })))),
            consts.into_iter()
        )
    );
}

#[test]
fn analyzer_fails() {
    //Creates an "analyzer" with properties and test that multiple properties
    //fail with their respective label on a single event.
    let mut a: Analyzer<'static, i32> = Analyzer::new()
        .add_property("XXX", bottom("bottom"))
        .add_property("YYY", bottom("bottom"))
        .add_property("ZZZ", top());
    let r = a.observe_event(&0);
    assert_eq!(r, Err(vec!["XXX".to_string(), "YYY".to_string()]));
}
