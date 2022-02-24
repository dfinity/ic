<h1>Overhead with varying payload size</h1>

<p>Purpose: Measure system overhead using a canister that does
essentially nothing for typical application subnetworks for increasing payload size.</p>

<pre class="w3-light-gray">
Deploy one instance of canister c
Run workload generators on multiple machines, increasing the payload size of given type until a given threshold of errors on client side
Measure and determine per iteration:
  Requests / second
  Error rate
  Request latency
  Flamegraph
Measure and determine globally:
  Maximum capacity max_cap (maximum payload size given acceptable latency and failure rate)
  Workload generator metrics per iteration
  Prometheus metrics (externally)
</pre>

<p>
  The result of this benchmark is the maximum payload size for {{type}} calls at {{experiment_details.rps}} requests per second.
</p>

<div>
  Request type: <b>{{type}}</b> on workload <b>{{workload}}</b> with payload sizes <b>{{experiment_details.payload_size}}</b>
</div>

<div>
  Maximum capacity determined so far:
  
  <div class="w3-tag w3-blue w3-round"> <span class="w3-xlarge">{{experiment_details.payload_size_max}}</span> bytes</div>
  
</div>
