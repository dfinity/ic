<h1>Experiment 2: Memory under load</h1>

Purpose: Measure memory performance for a canister that has a high memory demand.

<pre>
Deploy a single memory test canister which doubles memory occupation on update calls
Increase requests per second over time
Run workload generators on multiple machines with a fixed payload
Measure and determine per iteration:
  Requests / second 
  Error rate
  Request latency
  TODO Memory performance
  TODO AMD uProf L2 (page faults and cache misses on various levels)
  TODO AMD uProf memory (memory throughput demand of the system)
  Flamegraphs
Measure and dtermine globally:
  Workload generator metrics per iteration
  Prometheus metrics (externally)
</pre>

<div>
  Suggested success criteria (Queries): <br />
  Maximum number of queries not be below yyy queries per second with less than 20% failure and a maximum latency of 5000ms
</div>

<div>
  Suggested success criteria (Updates): <br />
  Maximum number of queries not be below xxx queries per second with less than 20% failure and a maximum latency of 10000ms
</div>

<div>
  Request type: <b>{{type}}</b> on workload <b>{{workload}}</b> with requests per second <b>{{experiment_details.rps}}</b>
</div>

<div>
  Maximum capacity determined so far:
  
  <div class="w3-blue"> {{experiment_details.rps_max}} {{type}} / second</div>
  
  <div class="w3-panel w3-leftbar w3-border-orange w3-sand">
    This is determined by the number of successful request the workload generator has recorded divided by the length
    of the iteration run. The latter might be longer than what is given as argument to the workload generator (-n), since
    some request might take long before they time out.
  </div>
</div>
