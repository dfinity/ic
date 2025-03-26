/// Define which canister requests should be picked in a round-robin workload generator, and at what frequencies.
/// The first argument is the workload index. See `Engine::new`.
/// The second and all consecutive arguments are (comma-separated) triples of the form
/// <frequency_literal> * <agent_expression> => <request_expression>
/// Here:
/// - <frequency_literal> is a literal defining how many times this request should be submitted in one round robin.
/// - <agent_expression> is an expression evaluating to a `CanisterAgent` instance that should submit the request.
/// - <request_expression> is an expression evaluating to a `canister_api::Request` instance.
///
/// Example usage:
/// ```
/// fn generate_workload(env: TestEnv) {
///     let future_generator = {
///         let agents: (CanisterAgent, CanisterAgent)  = todo!();
///         let request_provider: NnsDappRequestProvider = todo!();
///         let account: Account = todo!();
///         move |idx: usize| {
///             let agents = agents.clone();
///             async move {
///                 let agents = agents.clone();
///                 let request_outcome = canister_requests![
///                     idx,
///                     2 * agents.0 => request_provider.get_account_request(account, CallMode::Update),
///                     3 * agents.1 => request_provider.http_request("/main.js".to_string(), CallMode::Query),
///                 ];
///                 request_outcome.into_test_outcome()
///             }
///         }
///     };
///     // Configure the workload generation engine
///     let engine = Engine::new(env.logger(), future_generator, 100.0 /* RPS */, Duration::from_secs(60));
///     // Execute the workload generator and aggregate the metrics
///     let metrics = block_on(workload.execute(LoadTestMetrics::default(), LoadTestMetrics::aggregator_fn)).unwrap()
///     // Log the metrics s.t. they are added to the system test report.
///     env.emit_report(format!("{metrics}"));
/// }
/// ```
/// This will launch a workload generator that calls NNS canister endpoints at 100 RPS for 60 seconds. Each call is picked
/// from the following list in a round-robin manner (using pseudocode for simplicity):
/// 1. (agents.1).update("get_account_request", payload=account)
/// 2. (agents.1).update("get_account_request", payload=account)
/// 3. (agents.2).query("http_request", url="/main.js")
/// 4. (agents.2).query("http_request", url="/main.js")
/// 5. (agents.2).query("http_request", url="/main.js")
///
/// Thus, the frequencies of the calls is (2/5) * 100 = 40 RPS, and (3/5) * 100 = 60 RPS for the "get_account_request" and
/// "http_request" endpoints, resp.
#[macro_export]
macro_rules! canister_requests {
    ( $i:ident $(, $l:literal * $a:expr => $r:expr )+ $(,)? ) => {
        {
            let _num_requests: usize = canister_requests!(@count_requests $($l),+ );
            let mut _res: Option<RequestOutcome<(), anyhow::Error>> = None;
            let mut _j = 0usize;
            $(
                if (_j <= ($i % _num_requests) && ($i % _num_requests) < _j + (1usize * $l)) {
                    _res = Some(
                        $a.call(&$r).await.map(|_| ())
                    );
                }
                _j += (1usize * $l);
            )+
            _res.unwrap()
        }
    };
    (@count_requests) => (0usize);
    (@count_requests $head:literal $(, $tail:literal)* ) => (
        (1usize * $head) + canister_requests!(@count_requests $($tail),*)
    );
}
