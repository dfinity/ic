<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <title>Performance for {{githash}}</title>
    <script src="https://cdn.plot.ly/plotly-2.4.2.min.js"></script>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <style>
      plot {
          width: 100%;
      }

      .exp_value {
          min-width: 1em;
          min-height: 1em;
      }
    </style>
  </head>
<body>
  <div class="w3-container">
    Experiment timestamp: {{timestamp}}<br>
    Git hash: <a href="https://gitlab.com/dfinity-lab/core/ic/-/commit/{{githash}}">
      <i class="fa fa-brands fa-gitlab"></i> {{githash}}</a><br>
    Artifacts git hash:
    <a href="https://gitlab.com/dfinity-lab/core/ic/-/commit/{{experiment.artifacts_githash}}">
      <i class="fa fa-brands fa-gitlab"></i> {{experiment.artifacts_githash}}</a><br>
    Testnet: <a href="https://gitlab.com/dfinity-lab/core/ic/-/blob/master/testnet/env/{{experiment.testnet}}/hosts.ini">
      {{experiment.testnet}}</a><br>
    Workload generator testnet: <a href="https://gitlab.com/dfinity-lab/core/ic/-/blob/master/testnet/env/{{experiment.wg_testnet}}/hosts.ini">
      {{experiment.wg_testnet}}</a><br>
    Canister Id: {{experiment.canister_id}}<br>
    Subnet ID: {{experiment.subnet_id}}<br>
    Target Machine: <br>
    <ul>
      {{#each experiment.target_machines}}
      <li>{{this.name}} ({{this.host}} {{this.country}})
      {{/each}}
    </ul>
    
    Load Generator Machines: <br>
    <ul>
      {{#each experiment.load_generator_machines}}
      <li>{{this.name}} ({{this.host}} {{this.country}})
      {{/each}}
    </ul>
    Time experiment start: {{experiment.t_experiment_start}}<br>
    Time experiment end: {{experiment.t_experiment_end}}<br>

    <button onclick="showAccordion('lscpu')" class="w3-btn w3-green">📂 Show lscpu</button><br />
    <div id="lscpu" class="w3-container w3-hide">
      <pre class="w3-light-gray">
{{lscpu}}
</pre>
    </div>
    
    <button onclick="showAccordion('free')" class="w3-btn w3-green">📂 Show free</button><br />
    <div id="free" class="w3-container w3-hide">
      <pre class="w3-light-gray">
{{free}}
    </pre>
    </div>

    <button onclick="showAccordion('subnet_info')" class="w3-btn w3-green">📂 Show subnet_info</button><br />
    <div id="subnet_info" class="w3-container w3-hide">
      <pre class="w3-light-gray">
{{subnet_info}}
    </pre>
    </div>

    <button onclick="showAccordion('topology')" class="w3-btn w3-green">📂 Show topology</button><br />
    <div id="topology" class="w3-container w3-hide">
      <pre class="w3-light-gray">
{{topology}}
    </pre>
    </div>

    
    See <a href="https://docs.google.com/document/d/123I-dAzY7W8yVpGbys63Nx4QaaP9yvPIq-APdvMiUQg/edit#heading=h.b9iztisufxmz">here</a> for a complete list of experiments and their explanation.

    <h1>Grafana Dashboards</h1>

    For the time period of the experiment and the given testnets, those should be the relevant Grafana Dashboards:

    <ul>
      <li><a href="https://grafana.dfinity.systems/d/GWlsOrn7z/execution-metrics-2-0?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">Execution Metrics 2.0</a>
      <li><a href="https://grafana.dfinity.systems/d/yHCK_IFMz/resources?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">Message Routing</a>
      <li><a href="https://grafana.dfinity.systems/d/rnF_68BGk/http-handler?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">HTTP handler</a>
      <li><a href="https://grafana.dfinity.systems/d/q9w4oZWGz/ic-progress-clock?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">IC Progress Clock</a>
      <li><a href="https://grafana.dfinity.systems/d/IYNTCMIGk/state-sync?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">State Sync</a>
      <li><a href="https://grafana.dfinity.systems/d/u016YUeGz/workload-generator-metrics?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}&var-ic_workload_generator={{experiment.wg_testnet}}">Workload generator dashboard</a>
      <li><a href="https://grafana.dfinity.systems/d/YKZloKJMz/replica-details?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">Replica Details</a>
      <li><a href="https://grafana.dfinity.systems/d/oHBzMeMMk/xnet?orgId=1&from={{experiment.t_experiment_start}}000&to={{experiment.t_experiment_end}}000&&var-ic={{experiment.testnet}}">Xnet</a>
    </ul>
    

    {{{experiment-details}}}

    
    <h2>HTTP request latency</h2>

    This is measured by the replica

    <div id="plot-http-latency" style="width:600px;height:250px;"></div>
    <script>
      plot = document.getElementById('plot-http-latency');
      Plotly.newPlot( plot, {{{plot-http-latency}}}, {{{layout-http-latency}}} );
    </script>
    
    <h2>Median workload generator request latency</h2>
    
    This is measured by the workload generator (client side).
    It's the median latency over all requests, including failed ones.

    <div class="w3-panel w3-leftbar w3-border-orange w3-sand">
    Note that failed requests often have a low latency, as they immediately return
    or submitting a request might fail right away.
    Consequently, with more than half of the tests failing, the median is going to be
    one of the failed request and hence it will show a low latency in the following plot.</br>

    Check the maximum latency in each of the iterations below to get more details.
    </div>
    
    <div id="plot-wg-http-latency" style="max-height:500px;"></div>
    <script>
      plot = document.getElementById('plot-wg-http-latency');
      Plotly.newPlot( plot, {{{plot-wg-http-latency}}}, {{{layout-wg-http-latency}}} );
    </script>

    <h2>Workload generator failure rate</h2>

    This is measured by the workload generator (client side).

    <div id="plot-wg-failure-rate" style="max-height:500px;"></div>
    <script>
      plot = document.getElementById('plot-wg-failure-rate');
      Plotly.newPlot( plot, {{{plot-wg-failure-rate}}}, {{{layout-wg-failure-rate}}} );
    </script>

    <h2>Iterations</h2>

    Experiments run in iteration.
    In each experiment iteration, we increase stress on tye system.
    
    We collect metrics for those iterations individually.
    
    {{#each iterations}} 

    <h3>Iteration {{this.header}} ({{../experiment.xtitle}}: {{this.configuration.configuration.load_total}})</h3>
    99th percentile latency: {{this.t_99}}ms (mean from all workload generators)<br>
    Median latency: {{this.t_median}}ms (maximum from all workload generators)<br>
    Failure rate: <span class="w3-tag w3-round w3-{{this.failure_rate_color}}">
      {{this.failure_rate}}%</span><br>
    <button onclick="showAccordion('iteration-{{this.header}}')" class="w3-btn w3-green">📂 Show details for iteration {{this.header}}</button><br />
    <div id="iteration-{{this.header}}" class="w3-container w3-hide">

    Latency average: {{this.t_average}}ms<br>
    Latency max: {{this.t_max}}ms<br>
    Latency min: {{this.t_min}}ms<br>
    95th percentile latency: {{this.t_95}}ms<br>
    90th percentile latency: {{this.t_90}}ms<br>
    Total number of requests executed: {{this.total_requests}}<br>
    <br>
    Median finalization rate: {{this.prometheus.finalization_rate.1}}<br>
    Total load: {{this.configuration.configuration.load_total}}<br>
    <!-- HTTP request duration: {{this.prometheus.http_request_duration}} -->
    
{{#if this.prometheus.http_request_rate_plot }}
    <div id="plot-{{this.header}}-http-request-rate" style="width:600px;height:250px;"></div>
    <script>
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-{{this.header}}-http-request-rate');
          Plotly.newPlot( plot, {{{this.prometheus.http_request_rate_plot}}},  {{{this.prometheus.http_request_rate_layout}}});
      }, false);
    </script>
{{else}}
    <div>
      ⚠️  No HTTP request rate data
    </div>
{{/if}}

    Workload generator commands executed are:<br />
{{#each this.wg_commands}}      
    <div style="font-family: monospace" class="w3-light-gray">
      {{this}}
    </div>
{{/each}}    

    {{#if this.flamegraph}}
    <a href="{{this.flamegraph}}">
      <img src="{{this.flamegraph}}" alt="Flamegraph for iteration {{this.header}}" style="max-width: 600px;">
    </a>
    {{else}}
    <div>
      ⚠️  No flamegraph
    </div>
    {{/if}}

    </div>
    {{/each}}
    </div>

    <script>
      function showAccordion(id) {
          var x = document.getElementById(id);
          if (x.className.indexOf("w3-show") == -1) {
              x.className += " w3-show";
          } else { 
              x.className = x.className.replace(" w3-show", "");
          }
      }
    </script>

</body>
</html>
