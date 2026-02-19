use ic_cdk::{export_candid, update};

#[update]
async fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[update]
async fn echo(s: String) -> String {
    s
}

export_candid! {}

fn main() {}

#[cfg(test)]
mod tests {
    use candid_parser::utils::{service_equal, CandidSource};

    #[test]
    fn candid_equality_test() {
        let expected = include_str!("callee.did");
        let expected_candid = CandidSource::Text(expected);

        let actual = super::__export_service();
        let actual_candid = CandidSource::Text(&actual);

        let result = service_equal(expected_candid, actual_candid);
        assert!(result.is_ok(), "{:?}", result.unwrap_err());
    }
}
