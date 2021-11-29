<h1>Experiment 1: System baseline under load</h1>

<p>Purpose: Measure system overhead using a canister that does
essentially nothing for typical application subnetworks. Do so for a
canister in Rust and Motoko.</p>

<pre class="w3-light-gray">
Deploy one instance of canister c
Run workload generators on multiple machines, increasing requests of given type until a given threshold of errors on client side
Measure and determine per iteration:
  Requests / second
  Error rate
  Request latency
  Flamegraph
Measure and determine globally:
  Maximum capacity max_cap (maximum number of successful requests per second given acceptable latency and failure rate)
  Workload generator metrics per iteration
  Prometheus metrics (externally)
</pre>

<p>
Suggested success criteria (Queries):<br />
Maximum number of queries not be below yyy queries per second with less than 20% failure and a maximum latency of 5000ms
</p>

<p>
Suggested success criteria (Updates):<br />
Maximum number of queries not be below xxx queries per second with less than 20% failure and a maximum latency of 10000ms
</p>

<p>
Measure system overhead using a canister that does essentially nothing for typical application subnetworks. Do so for a canister in Rust and Motoko.<br>
</p>

<p>
  The result of this benchmark is the maximum capacity for {{type}} calls.
  It is defined as the highest successful number of query calls per second 
</p>

<div>
  Request type: <b>{{type}}</b> on workload <b>{{workload}}</b> with requests per second <b>{{experiment_details.rps}}</b>
</div>

<div>
  Maximum capacity determined so far:
  
  <div class="w3-tag w3-blue w3-round"> <span class="w3-xlarge">{{experiment_details.rps_max}}</span> {{type}} / second</div>
  
  <div class="w3-panel w3-leftbar w3-border-orange w3-sand">
    This is determined by the number of successful request the workload generator has recorded divided by the length
    of the iteration run. The latter might be longer than what is given as argument to the workload generator (-n), since
    some request might take long before they time out.
  </div>
</div>
