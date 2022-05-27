<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <title>Performance for {{githash}}</title>
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
    <h1>Estimated mainnet performance</h1>

    <div>
      Based on numbers from: <span class="timestamp">{{last_generated}}</span><br />
      Assuming mainnet has <span class="w3-tag w3-light-grey exp_value">{{num_app_subnets}}</span> application subnets running
      <span class="w3-tag w3-light-grey exp_value">{{num_app_nodes}}</span> nodes.
    </div>

    Per subnet, that is: 
    <div class="w3-btn w3-green w3-large">
      {{latest_approx_mainnet_subnet_update_performance}} updates/s
    </div>

    and per IC node:
    <div class="w3-btn w3-green w3-large">
      {{latest_approx_mainnet_node_query_performance}} querys/s
    </div>
    
    <div>
      Extrapolated from those latest performance runs, mainnet would sustain the following load:
    </div>

    <div class="w3-btn w3-green w3-large">
      {{latest_approx_mainnet_update_performance}} updates/s
    </div>

    <div class="w3-btn w3-green w3-large">
      {{latest_approx_mainnet_query_performance}} querys/s
    </div>

    <h1>Energy consumption</h1>

    <div>
      The following is an approximation of mainnet power consumption.
      The peak power consumption of our nodes is <span class="w3-tag w3-light-grey exp_value">{{watts_per_node}}W</span>.
    </div>
    
    <div>
      If we assume a power usage effectiveness (PUE)
      <sup>
        <a href="https://en.wikipedia.org/wiki/Power_usage_effectiveness">1,</a>
        <a href="https://energyinnovation.org/2020/03/17/how-much-energy-do-data-centers-really-use/">2</a>,
      </sup>
      of, <span class="w3-tag w3-light-grey exp_value">{{pue}}</span>
      that leads to a total power consumption of <span class="w3-tag w3-light-grey exp_value">{{watts_per_node_total}}W</span>
      including cooling and other data center operations csosts.
    </div>
    
    <div>
      Given a total of <span class="w3-tag w3-light-grey exp_value">{{num_nodes}}</span> nodes
      and <span class="w3-tag w3-light-grey exp_value">{{num_boundary_nodes}}</span> boundary nodes in mainnet, that results in a
      worst case of <span class="w3-tag w3-light-grey exp_value">{{watts_ic}}W</span> to operate all IC nodes for mainnet.
      That's a worst case analysis for power consumption of nodes because we would normally expect them to throttle
      when not fully utilized and thereby reducing power consumption.
    </div>
    
    <div>
      Given the maximum rate of upates and queries that we can
      currently support in the IC, one update call would consume
      <span class="w3-tag w3-light-grey exp_value">{{joules_per_update_at_capacity}}J</span> (Joules) and one query call
      <span class="w3-tag w3-light-grey exp_value">{{joules_per_query_at_capacity}}J</span>. Those numbers are for a
      hypothetical fully utilized IC.
    </div>
    
    <div>
      With the current approximate rate of <span class="w3-tag w3-light-grey exp_value">{{transaction_current}}</span> transactions/s,
      the IC needs <span class="w3-tag w3-light-grey exp_value">{{joules_per_transaction_current}}J</span> per transaction.
    </div>
    
    <h1>CD performance results</h1>

    <h2>Experiment 1: System baseline under load</h2>

    <p>
      Purpose: Measure system overhead using a canister that does
      essentially nothing for typical application subnetworks.
    </p>

    <h3>Query calls</h3>

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

    <div class="w3-dropdown-hover">
      <button class="w3-button">Show list of detailed reports</button>
      <div class="w3-dropdown-content w3-bar-block w3-border" style="min-width: 250px;">
        {{#each plot_exp1_query.data}}
        <a href="{{this.githash}}/{{this.timestamp}}/report.html" class="w3-bar-item w3-button">
          {{this.date}}
        </a>
        {{/each}}
      </div>
    </div>

    <h3>Update calls</h3>

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

    <div class="w3-dropdown-hover">
      <button class="w3-button">Show list of detailed reports</button>
      <div class="w3-dropdown-content w3-bar-block w3-border" style="min-width: 250px;">
        {{#each plot_exp1_update.data}}
        <a href="{{this.githash}}/{{this.timestamp}}/report.html" class="w3-bar-item w3-button">
          {{this.date}}
        </a>
        {{/each}}
      </div>
    </div>

    <h2>Experiment 2: Memory under load</h2>

    <p>
      Purpose: Measure memory performance for a canister that has a high memory demand.
    </p>

    <h3>Update</h3>

    <p>In contrast to query calls, when executing the memory load benchmark with update calls,
      orthogonal persistence and snapshots needs to be done for the memory pages touched.</p>


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

    <div class="w3-dropdown-hover">
      <button class="w3-button">Show list of detailed reports</button>
      <div class="w3-dropdown-content w3-bar-block w3-border" style="min-width: 250px;">
        {{#each plot_exp2_update.data}}
        <a href="{{this.githash}}/{{this.timestamp}}/report.html" class="w3-bar-item w3-button">
          {{this.date}}
        </a>
        {{/each}}
      </div>
    </div>

    <h3>Query</h3>

    <div id="plot-exp2-query" class="plot"></div>
    <script>
      const plot_exp2_query_links = new Map();
      {{#each plot_exp2_query.data}}
        plot_exp2_query_links.set(("{{this.xvalue}}", {{this.yvalue}}), "{{this.githash}}/{{this.timestamp}}/report.html");
      {{/each}}
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp2-query');
          Plotly.newPlot( plot, {{{ plot_exp2_query.plot }}},  {{{plot_exp2_query.layout}}});
          plot.on('plotly_click', function(data) {
              var link = '';
              for(var i=0; i < data.points.length; i++){
                  link = plot_exp2_query_links.get((data.points[i].x, data.points[i].y));
              }
              window.open(link, "_self");
          });

      }, false);
    </script>

    <div class="w3-dropdown-hover">
      <button class="w3-button">Show list of detailed reports</button>
      <div class="w3-dropdown-content w3-bar-block w3-border" style="min-width: 250px;">
        {{#each plot_exp2_query.data}}
        <a href="{{this.githash}}/{{this.timestamp}}/report.html" class="w3-bar-item w3-button">
          {{this.date}}
        </a>
        {{/each}}
      </div>
    </div>

  </div>
</body>
