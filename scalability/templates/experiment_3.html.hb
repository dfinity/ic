<h1>Experiment 3: Management of large number of canisters</h1>

<p>Purpose: Measure how latency is affected by the number of canisters.
This would be similar to the kinds of workloads that we would expect for OpenChat v2.</p>

<pre>
For request type t in { Query, Update }
  For canister c in { Rust nop, Motoko nop }

    Topology: 13 node subnet, 1 machine NNS
    Deploy an increasing number of canisters c
    Run workload generators on 13 machines at 70% max_cap after each increase in canister count
    Measure and determine:
      Requests / second 
      Error rate
      Request latency
      Flamegraph
      Statesync metrics (e.g. duration)
      Workload generator metrics
</pre>

Suggested success criteria: <br />
xxx canisters can be installed in a maximum of yyy seconds
