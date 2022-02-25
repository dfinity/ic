<h1>Experiment 1: System baseline under load</h1>

<p>
  Purpose: Measure system overhead using the counter canister (written in wat).
  The counter caniste can be considered a no-op canister, since it almost immediately returns,
  making it useful to measure the system overhead.
</p>

<pre class="w3-light-gray">
Deploy one instance of counter canister c
Run workload generators on multiple machines, iteratively increasing requests of given type
Measure and determine per iteration:
  Requests rate (requests/s)
  Error rate
  Request latency
  Flamegraph
  Workload generator metrics per iteration
Measure and determine globally:
  Maximum capacity max_cap (maximum number of successful requests per second given acceptable latency and failure rate)
  Prometheus metrics (externally)
</pre>

<p>
The system is considered healthy iff:
<ul>
  <li>The failure rate perceived by the workload generators is less than:
    <span class="w3-tag w3-light-grey exp_value">{{experiment_details.allowable_failure_rate}}</span>
  <li>The median latency is less than:
    <span class="w3-tag w3-light-grey exp_value">{{experiment_details.allowable_t_median}}</span>
</ul>
</p>

<p>
  The result of this benchmark is the maximum capacity for <span class="w3-tag w3-light-grey exp_value">{{type}}</span> calls.
  It is calculated from the number of successful request in one benchmark iteration divided by the duration of that iteration.
  An iteration is only considered for maximum capacity if the system is still healthy according to the defintion above.
</p>

<div>
  <ul>
    <li>Request type: <span class="w3-tag w3-light-grey exp_value">{{type}}</span>
    <li>Workload: <span class="w3-tag w3-light-grey exp_value">{{workload}}</span>
    <li>Requests per second: <span class="w3-tag w3-light-grey exp_value">{{experiment_details.rps}}</span>
    <li>Duration of load generation in each iteration:
      <span class="w3-tag w3-light-grey exp_value">{{experiment_details.duration}}</span> vs. target duration of
      <span class="w3-tag w3-light-grey exp_value">{{experiment_details.target_duration}}</span>
  </ul>
</div>

<div>
  <div>
    Maximum capacity determined:
    <div class="w3-tag w3-blue w3-round">
      <span class="w3-xlarge">{{experiment_details.rps_max}}</span> {{type}} / second
    </div>
    (achieved in iteration with {{experiment_details.rps_max_in}} requests per second)
  </div>
  
  
  <div class="w3-panel w3-leftbar w3-border-orange w3-sand">
    This is determined by the number of successful request the workload generator has recorded divided by the length
    of the iteration run. The latter might be longer than what is given as argument to the workload generator (-n), since
    some request might take long before they time out.
  </div>
</div>
