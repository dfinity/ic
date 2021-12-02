<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <title>Performance for {{githash}}</title>
    <script src="https://cdn.plot.ly/plotly-2.4.2.min.js"></script>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="templates/style.css">
  </head>
<body>
  <div class="w3-container">
    <h1>CD performance results</h1>

    <h2>Experiment 1: System baseline under load</h2>

    <p>
      Purpose: Measure system overhead using a canister that does
      essentially nothing for typical application subnetworks.
    </p>

    <h2>Query calls</h2>

    <div id="plot-exp1-query" class="plot"></div>
    <script>
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp1-query');
          Plotly.newPlot( plot, {{{plot_exp1_query.plot}}},  {{{plot_exp1_query.layout}}});
      }, false);
    </script>

    <h2>Update calls</h2>

    <div id="plot-exp1-update" class="plot"></div>
    <script>
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp1-update');
          Plotly.newPlot( plot, {{{plot_exp1_update.plot}}},  {{{plot_exp1_update.layout}}});
      }, false);
    </script>


    <h2>Experiment 2: Memory under load</h2>

    <p>
      Purpose: Measure memory performance for a canister that has a high memory demand.
    </p>

    <div id="plot-exp2-update" class="plot"></div>
    <script>
      window.addEventListener("load", function(event) {
          plot = document.getElementById('plot-exp2-update');
          Plotly.newPlot( plot, {{{ plot_exp2_update.plot }}},  {{{plot_exp2_update.layout}}});

      }, false);
    </script>

  </div>
</body>
