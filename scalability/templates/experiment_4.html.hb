<h1>P0 Experiment 4: Gossip</h1>

<p>Purpose: Stress P2P layer with and without boundary node rate limiting and having a lot of clients (currently not investigated by the networking team).<br />
See presentation from networking team.</p>

<pre>
Topology: 13 node subnet, 1 machine NNS
Deploy one instance of the counter or nop canister
Start the workload generator to generate some load
Incrementally add nodes up to 50 nodes until performance degrades
Measure and determine:
    Requests / second 
    Error rate
    Request latency
    P2P metrics
    Workload generator metrics
</pre>

<p>Request type: <b>{{type}}</b> on workload <b>{{workload}}</b>.</p>
