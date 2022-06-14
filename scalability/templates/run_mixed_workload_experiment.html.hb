<h1>Mixed workload experiment: {{experiment_details.title}}</h1>

<p>
  Purpose: {{experiment_details.description}}
</p>

{{#each toml}}
toml
<pre class="w3-light-gray">
  {{this}}
</pre>
{{/each}}
