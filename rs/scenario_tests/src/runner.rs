use colored::*;
use core::future::Future;
use tester::{
    assert_test_result, test_main, DynTestFn, ShouldPanic, StaticTestName, TestDesc, TestDescAndFn,
    TestType,
};

/// This function reuses and tweaks the code generally used by cargo test.
/// This will work both when called by 'cargo run' and 'cargo test', although
/// test somewhat mangles the output.
/// This currently doesn't check that failing tests are actually failing
pub fn runner(tests: Vec<Test>, args: Vec<String>) {
    fn partition_map<A, O, E, F: Fn(A) -> Result<O, E>>(v: Vec<A>, f: F) -> (Vec<O>, Vec<E>) {
        v.into_iter()
            .fold((Vec::new(), Vec::new()), |(mut oks, mut errs), elem| {
                match f(elem) {
                    Ok(v) => oks.push(v),
                    Err(v) => errs.push(v),
                };
                (oks, errs)
            })
    }

    let (should_pass, should_fail) = partition_map(tests, passing);

    println!("Scenario tests:");
    for test in &should_pass {
        println!("\t{0}  Running {1}", "✔".green(), test.desc.name)
    }

    test_main(&args, should_pass, None);

    for test in should_fail {
        match test {
            Test::Passing(_) => panic!("This should be impossible"),
            Test::Failing(test, excuse, name) => {
                let name_and_shame = match name {
                    Some(name) => format!("and it's {}'s job to fix it", name.red()),
                    None => "".to_string(),
                };
                println!(
                    "\t{0} {1} was not run because {2} {3}",
                    "✘".red(),
                    test.desc.name,
                    excuse,
                    name_and_shame,
                )
            }
        }
    }
    println!();
}

pub fn failing_test<F>(
    test_name: &'static str,
    test: F,
    excuse: &str,
    assignee: Option<&str>,
) -> Test
where
    F: FnOnce() + Send + 'static,
{
    let mut test = test_builder(test_name, test);
    test.desc.allow_fail = true;
    Test::Failing(test, excuse.to_string(), assignee.map(|s| s.to_string()))
}

pub fn failing_test_async<Fut>(
    test_name: &'static str,
    test: impl FnOnce() -> Fut + Send + 'static,
    excuse: &str,
    assignee: Option<&str>,
) -> Test
where
    Fut: Future<Output = ()>,
{
    let mut test = test_builder(test_name, move || {
        tokio::runtime::Runtime::new().unwrap().block_on(test())
    });
    test.desc.allow_fail = true;
    Test::Failing(test, excuse.to_string(), assignee.map(|s| s.to_string()))
}

pub fn passing_test<F>(name: &'static str, test: F) -> Test
where
    F: FnOnce() + Send + 'static,
{
    Test::Passing(test_builder(name, test))
}

pub fn passing_test_async<Fut>(
    name: &'static str,
    test: impl FnOnce() -> Fut + Send + 'static,
) -> Test
where
    Fut: Future<Output = ()>,
{
    passing_test(name, move || {
        tokio::runtime::Runtime::new().unwrap().block_on(test())
    })
}

pub enum Test {
    Passing(TestDescAndFn),
    Failing(TestDescAndFn, String, Option<String>),
}

fn passing(t: Test) -> Result<TestDescAndFn, Test> {
    match t {
        Test::Passing(t) => Ok(t),
        t => Err(t),
    }
}

#[allow(clippy::unit_arg)]
fn test_builder<F>(name: &'static str, test: F) -> TestDescAndFn
where
    F: FnOnce() + Send + 'static,
{
    TestDescAndFn {
        desc: TestDesc {
            name: StaticTestName(name),
            ignore: false,
            allow_fail: false,
            should_panic: ShouldPanic::No,
            test_type: TestType::Unknown,
        },
        testfn: DynTestFn(Box::new(|| assert_test_result(test()))),
    }
}

#[cfg(test)]
fn test_fail() {
    panic!("Oh no!")
}

#[cfg(test)]
pub fn test_pass() {}

/// Here is an example of how to use this testing framework
#[test]
#[ignore]
pub fn run_tests() {
    runner(
        vec![
            passing_test("Example passing test", test_pass),
            failing_test(
                "Example failing test",
                test_fail,
                "the test is not implemented",
                None,
            ),
        ],
        vec![],
    )
}

// It's actually impossible to use should_panic on this function because of the
// way the rust test framework interacts with itself
#[ignore]
#[test]
pub fn run_tests_and_fail() {
    runner(
        vec![passing_test("Example failing test", test_fail)],
        vec![],
    )
}
