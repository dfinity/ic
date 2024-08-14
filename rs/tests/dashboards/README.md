# Production Grafana Dashboards

_Originally taken from [dfinity-lab/pfops](https://github.com/dfinity-lab/pfops/tree/master/environments/mainnet/dashboards)._

Grafana dashboard definitions for production dashboards.

Many of these dashboards are used for IC Support troubleshooting (and are
referenced by various runbooks) and thus should not allow  arbitrary edits.
But provisioning also allows the same dashboard to be available across different
Grafana instances (e.g. mainnet and testnet) so that is another use case.

## Making edits to provisioned dashboards

Provisioned dashboards can be edited normally from the Grafana UI, but the edits
cannot be saved. In order to persist the edits (and have them deployed to both
Grafana instances automatically):

 * Reset the filters and time range to their default values (the values they
   have when you load the dashboard from the dashboard browser; or if you load
   the dashboard after having removed all query arguments from the URL; do note
   that if you open the dashboard via a link from another dashboard, the filters
   and time range might carry over from there).
 * Click on the *Dashboard settings* button (the gear icon next to the time
   range selector).
 * Select *JSON Model* from the left hand menu.
 * Copy the dashboard's JSON definition and paste it into the corresponding file
   in this directory.
   
## Reviewing changes to provisioned dashboards

Ensure that the changes are described sufficiently in the PR description. Furthermore,
double check that the dashboard is still loading and generally working with the new JSON
model. To do this:

* Click on the *Dashboard settings* button (the gear icon next to the time
   range selector).
* Select *JSON Model* from the left hand menu.
* Copy the JSON definition from the PR into the dashboard's JSON definition.
* Update the fields "title" and "uid" at the very bottom by e.g. appending " - Temp" to
  the "title" field and "_temp" to the "uid" field.
* Hit "Save changes". A new dashboard with the name you chose in the above step should be
  available for inspection.
* Ensure the changes look good on the temp dashboard.
* Once you're done delete the temp dashboard.
* Click on the *Dashboard settings* button (the gear icon next to the time
   range selector).
* On the general settings you should see a button to delete the temp dashboard.

## Adding new dashboards

A new dashboard can be added to the set of provisioned dashboards simply by
adding a `.json` file with the dashboard definition anywhere under this
directory. It will then be deployed automatically to both the mainnet and
testnet Grafana instances.

Tip: It is useful to change the value of the `"uid"` field in the JSON with the
name of the dashboard with spaces and other special characters replaced by dashes
(e.g. `"ic-progress-clock"` for the IC Progress Clock dashboard). That way the
dashboard can be quickly accessed by typing e.g.
`grafana.mainnet.dfinity.network/d/ic-progress-clock` into the address bar.
