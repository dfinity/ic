<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <title>IC Performance Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-2.4.2.min.js"></script>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="templates/style.css">
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

    <h3>Query call maximum capacity</h3>

    <p>
      For query workloads we currently target 4000 queries/second per node in each subnetwork (red line in the plot).
    </p>
    
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

    <h3>Update calls</h3>

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

    <p>
      Purpose: Measure memory performance for a canister that has a high memory demand.<br />
      Memory management on the IC is an expensive operation and this workload is expected to stress the memory subsystem.
      We expect a much lower request rate in this benchmark.
    </p>

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

    <p>
      Purpose: Measure the duration of state sync after a machine has been down for a few checkpoints while
      issuing a lot of updates to the state sync test canister.
    </p>

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

    <h2>Maximum Xnet capacity</h2>

    <p>
      Purpose: Measure the maximum capacity of all-to-all Xnet communication.<br />
      The benchmark executes an all to all communiation tests and determines the maximum message throughput achieved
      in the experiment.<br />
      This is important since many canisters need to communicate with other canisters to complete user requests.
      The total number of such calls is cruicial for scaling up the IC.
      
      {{! <table> }}
      {{!   <tr> }}
      {{!     <td>Canister</td> }}
      {{!     <td>Benchmark</td> }}
      {{!   </tr> }}
      {{!   <tr> }}
      {{!     <td></td> }}
      {{!     <td></td> }}
      {{!   </tr> }}
      {{! </table> }}
      
    </p>

    <div style="background-color: orange;">
      This benchmark is currently broken. We leave it here so that we do not forget about it and put some pressure to fix it.
    </div>

    <div id="plot-xnet" class="plot"></div>
    <script>
      const plot_xnet_links = new Map();
      {{#each plot_xnet.data}}
        plot_xnet_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-xnet');
          Plotly.newPlot( plot, {{{ plot_xnet.plot }}},  {{{plot_xnet.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_xnet_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>
  </div> <!-- Container //-->
</body>
