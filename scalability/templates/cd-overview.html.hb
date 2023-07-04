<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <title>IC Performance Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-2.4.2.min.js"></script>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="templates/style.css">
    <style>
      pre {
        background-color: #efefef;
        font-family: monospace;
        font-size: small;
      }
    </style>
    <script>
      function display_times() {
          let timestamps = document.getElementsByClassName("timestamp");
          for (var i=0; i < timestamps.length; i++) {
              let ts = timestamps[i].innerHTML;
              let date = new Date(parseInt(ts * 1000));
              timestamps[i].innerHTML = "<span class=\"w3-tag w3-light-grey exp_value\">" + date + "</span>"
          }
      }
    </script>
  </head>
<body onload="display_times()">
  <div class="w3-container">
    <div style="position: absolute; top: 0px; right: 0px; padding: 2em;">
      <img src="fully_on_chain-default-bg_dark.svg" alt="On-chain logo" style="width: 10em;" />
    </div>
    <h1>CD performance results</h1>

    <p>
      This page containes history data of our internal performance evaluation pipeline.
      We run our benchmarks on a dedicated testnet, which aims to accurately represent
      performance of a mainnet subnet (hoever, in reality, though, testnets only have about half
      of the compute capacity as nodes on mainnet).<br />
      Data on this page is aggregated from individual benchmark runs.
    </p>

    <h2>Experiment 1: System baseline under load</h2>
    <a name="system_baseline" />

    <p>
      Purpose: Measure system overhead using a canister that does
      essentially nothing for typical application subnetworks.<br />
      Therefore, the expectation is that we will be bottlenecked by the system overhead in those benchmarks.
      It is trivially possible to move the bottleneck elsewhere, e.g. to the runtime component for
      heavy queries.
    </p>
    <p>
      We measure the maximum throughput of successful requests at various input request rates.
      If the failure rate and the p90 latency becomes inacceptable, we stop to increase the load further.
    </p>

    <div id="canister_code">
      <span>Canister code:</span> <a href="https://gitlab.com/dfinity-lab/public/ic/-/blob/master/rs/workload_generator/src/counter.wat">counter.wat</a>
    </div>

    <h3>Query call maximum capacity</h3>
    <a name="sys-baseline-queries" />

    <p>
      For query workloads we currently target 4000 queries/second per node in each subnetwork (red line in the plot).
    </p>

    <h4>Query capacity</h4>

    <div id="plot-exp1-query" class="plot"></div>
    <script>
      const plot_exp1_links = new Map();
      {{#each plot_exp1_query.data}}
        plot_exp1_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}

      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp1-query');
          Plotly.newPlot(plot, {{{plot_exp1_query.plot}}},  {{{plot_exp1_query.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp1_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });
      }, false);
    </script>

    <p>
      For query workloads the follwing plots show latency and failure rates. Each plot tracks the latency or failure rate over time.
      As we have changed the requests rates that we are running in weekly benchmarks, some plots end and other ones start.
      The goal is for all of them to never increase over time.
    </p>

    <h4>Failure rate</h4>
    <div id="plot_exp1_query_failure_rate" class="plot"></div>
    <script>
      const plot_exp1_links_failure_rate = new Map();
      {{#each plot_exp1_query_failure_rate.data}}
        plot_exp1_links_failure_rate.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}

      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_exp1_query_failure_rate');
          Plotly.newPlot(plot, {{{plot_exp1_query_failure_rate.plot}}},  {{{plot_exp1_query_failure_rate.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp1_links_failure_rate.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });
      }, false);
    </script>

    <h4>Latency</h4>
    <div id="plot_exp1_query_latency" class="plot"></div>
    <script>
      const plot_exp1_links_latency = new Map();
      {{#each plot_exp1_query_latency.data}}
        plot_exp1_links_latency.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}

      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_exp1_query_latency');
          Plotly.newPlot(plot, {{{plot_exp1_query_latency.plot}}},  {{{plot_exp1_query_latency.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp1_links_latency.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });
      }, false);
    </script>

    <h3>Update calls</h3>
    <a name="sys-baseline-updates" />

    <p>
      We currently expect to see around 800 updates/second per subnetwork (red line in the plot)
    </p>

    <div id="plot-exp1-update" class="plot"></div>
    <script>
      const plot_exp1_update_links = new Map();
      {{#each plot_exp1_update.data}}
        plot_exp1_update_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp1-update');
          Plotly.newPlot( plot, {{{plot_exp1_update.plot}}},  {{{plot_exp1_update.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp1_update_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });
      }, false);
    </script>

    <h2>Experiment 2: Memory under load</h2>
    <a name="memory" />

    <p>
      Purpose: Measure memory performance for a canister that has a high memory demand.<br />
      Memory management on the IC is an expensive operation and this workload is expected to stress the memory subsystem.
      We expect a much lower request rate in this benchmark.
    </p>

    <div id="canister_code">
      <span>Canister code:</span> <a href="https://gitlab.com/dfinity-lab/public/ic/-/tree/master/rs/rust_canisters/memory_test">memory_test canister</a>
    </div>

    <h3>Update</h3>

    <p>When executing the memory load benchmark with update calls,
      orthogonal persistence and snapshots needs to be done for the memory pages touched.<br />
    </p>

    <div id="plot-exp2-update" class="plot"></div>
    <script>
      const plot_exp2_update_links = new Map();
      {{#each plot_exp2_update.data}}
        plot_exp2_update_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp2-update');
          Plotly.newPlot( plot, {{{ plot_exp2_update.plot }}},  {{{plot_exp2_update.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp2_update_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>State Sync duration</h2>
    <a name="state-sync" />

    <p>
      Purpose: Measure the duration of state sync after a machine has been down for a few checkpoints while
      issuing a lot of updates to the state sync test canister.
    </p>

    <div id="canister_code">
      <span>Canister code:</span> <a href="https://gitlab.com/dfinity-lab/public/ic/-/tree/master/rs/rust_canisters/statesync_test">statesync test canister</a>
    </div>

    <div id="plot-statesync" class="plot"></div>
    <script>
      const plot_statesync_links = new Map();
      {{#each plot_statesync.data}}
        plot_statesync_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-statesync');
          Plotly.newPlot( plot, {{{ plot_statesync.plot }}},  {{{plot_statesync.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_statesync_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>Motoko QR code performance</h2>
    <a name="motoko_qr" />

    <p>
      Purpose: Motoko's QR benchmark<br />
      The benchmark code is rather naively written: Because of the awaits in a loop, there will be quite a few context switches and those might be flooding the canisiter with overlapping requests
    </p>

   <div id="canister_code">
      <span>Canister code:</span> <a href="https://github.com/dfinity/motoko/blob/master/test/perf/qr.mo">qr.mo</a>
    </div>

    <div style="background-color: orange;">
      Note that the canister wasm needs to be manually updated in the ic repo to reflect changes in Motoko.
    </div>

    <h3>Failure rate</h1>
    <div id="plot_qr" class="plot"></div>
    <script>
      const plot_qr_links = new Map();
      {{#each plot_qr.data}}
        plot_qr_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_qr');
          Plotly.newPlot( plot, {{{ plot_qr.plot }}},  {{{plot_qr.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_qr_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h3>Latency [ms]</h1>

    <div id="plot_qr_latency" class="plot"></div>
    <script>
      const plot_qr_latency_links = new Map();
      {{#each plot_qr_latency.data}}
        plot_qr_latency_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_qr_latency');
          Plotly.newPlot( plot, {{{ plot_qr_latency.plot }}},  {{{plot_qr_latency.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_qr_latency_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>Motoko sha256 performance</h2>
    <a name="motoko-sha256" />

    <p>
      Purpose: Motoko's sha256 benchmark
    </p>

   <div id="canister_code">
      <span>Canister code:</span> <a href="https://github.com/dfinity/motoko/blob/master/test/perf/sha256.mo">sha256.mo</a>
    </div>

    <div style="background-color: orange;">
      Note that the canister wasm needs to be manually updated in the ic repo to reflect changes in Motoko.
    </div>

    <h3>Failure rate</h1>
    <div id="plot_sha256" class="plot"></div>
    <script>
      const plot_sha256_links = new Map();
      {{#each plot_sha256.data}}
        plot_sha256_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_sha256');
          Plotly.newPlot( plot, {{{ plot_sha256.plot }}},  {{{plot_sha256.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_sha256_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h3>Latency [ms]</h1>
    <div id="plot_sha256_latency" class="plot"></div>
    <script>
      const plot_sha256_latency_links = new Map();
      {{#each plot_sha256_latency.data}}
        plot_sha256_latency_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_sha256_latency');
          Plotly.newPlot( plot, {{{ plot_sha256_latency.plot }}},  {{{plot_sha256_latency.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_sha256_latency_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>HTTP outcall feature benchmark</h2>
    <a name="http-outcall" />

    <p>
      Stress HTTP outcall feature from multiple canister.
    </p>
    <p>
      A total of 8 HTTP outcall canisters are benchmarked, 4 of which executed <pre>send_request</pre> using with payload <pre>4449444c066c02cfbe93a404018daacd9408786c06efd6e40271e1edeb4a02a2f5ed880471ecdaccac0403abd5bc96067fc6a4a19806046b019681ba027f6b0198d6caa201716d056c02f1fee18d0371cbe4fdc7047101001768747470733a2f2f7777772e6578616d706c652e636f6d000000095472616e73666f726d0103646566036162630088526a74000000</pre> which is:
      <pre>
'(
    record {
        cycles=500000000000:nat64;
        request=record{
            url="https://www.example.com";
            max_response_byte=null;
            headers=vec{ record { name="abc"; value="def" } };
            body="";
            method=variant { get };
            transform=variant { function = "Transform" }
        }
    }
)'
      </pre><br />
      The other 4 call <pre>check_response</pre> using with payload <pre>4449444c0001711768747470733a2f2f7777772e6578616d706c652e6f7267</pre> whitch is:
      <pre>
'( "https://www.example.com" )'
      </pre>
    </p>

    <div id="canister_code">
      <span>Canister code:</span> <a href="https://gitlab.com/dfinity-lab/public/ic/-/tree/master/rs/rust_canisters/proxy_canister">proxy canister</a>
    </div>

    <h3>Failure rate</h1>
    <div id="plot_http_outcall" class="plot"></div>
    <script>
      const plot_http_outcall_links = new Map();
      {{#each plot_http_outcall.data}}
        plot_http_outcall_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_http_outcall');
          Plotly.newPlot( plot, {{{ plot_http_outcall.plot }}},  {{{plot_http_outcall.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_http_outcall_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h3>Latency [ms]</h1>
    <div id="plot_http_outcall_latency" class="plot"></div>
    <script>
      const plot_http_outcall_latency_links = new Map();
      {{#each plot_http_outcall_latency.data}}
        plot_http_outcall_latency_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_http_outcall_latency');
          Plotly.newPlot( plot, {{{ plot_http_outcall_latency.plot }}},  {{{plot_http_outcall_latency.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_http_outcall_latency_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>Mixed update query workload</h2>

    <p>
      Purpose: Run a mixed update/query workload on the counter canister.</a>.
    </p>

    <div id="canister_code">
      <span>Canister code:</span> <a href="https://gitlab.com/dfinity-lab/public/ic/-/blob/master/rs/workload_generator/src/counter.wat">counter.wat</a>
    </div>

    <h3>Failure rate</h1>
    <div id="plot_mixed_counter" class="plot"></div>
    <script>
      const plot_mixed_counter_links = new Map();
      {{#each plot_mixed_counter.data}}
        plot_mixed_counter_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_mixed_counter');
          Plotly.newPlot( plot, {{{ plot_mixed_counter.plot }}},  {{{plot_mixed_counter.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_mixed_counter_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h3>Latency [ms]</h1>
    <div id="plot_mixed_counter_latency" class="plot"></div>
    <script>
      const plot_mixed_counter_latency_links = new Map();
      {{#each plot_mixed_counter_latency.data}}
        plot_mixed_counter_latency_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_mixed_counter_latency');
          Plotly.newPlot( plot, {{{ plot_mixed_counter_latency.plot }}},  {{{plot_mixed_counter_latency.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_mixed_counter_latency_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <h2>Runtime of other benchmarks</h2>

    <p>
      For various other benchmarks, we plot the sum of all iteration runtimes as a sanity check.</ br>
      This generic way of plotting results of course is not great, but it is better than nothing.
    </p>

    <div id="plot_experiment_time" class="plot"></div>
    <script>
      const plot_experiment_time_links = new Map();
      {{#each plot_experiment_time.data}}
        plot_experiment_time_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot_experiment_time');
          Plotly.newPlot( plot, {{{ plot_experiment_time.plot }}},  {{{plot_experiment_time.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_experiment_time_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

  </div> <!-- Container //-->
</body>
