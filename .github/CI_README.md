GitHub CI for the IC Repo

## Adding a new CI workflow
If your workflow is not complex, simply add the workflow to the `workflows` directory. See existing examples. If your workflow is more complex, see Generating CI yaml files below/

## Generating CI yaml files
Due to some limitations of GitHub Actions CI, we need to generate our own CI yaml files for our more complex pipelines. This is so we can use yaml anchors and re-use the same job setup. To add a new generated workflow:

1. Add your new workflow to `workflow-source`. Include any anchors you would like to use under the block `anchors`. If you name it something else, it will break.
1. Push your changes to GitHub which will trigger CI. This will automatically run a custom script (`generate-ci.py`) which will generate the full yaml file from your anchors, as well as delete the `anchors` block, as this will not work for github actions. This new yaml file will automatically be placed in the `workflows` directory.
1. Check that this new workflow file is correct.
