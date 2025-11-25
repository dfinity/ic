# Local Rosetta API Cluster

This directory contains scripts and configurations for setting up a local Kubernetes cluster using Minikube to deploy the Rosetta API services. The cluster includes monitoring tools such as Prometheus, cAdvisor, and Grafana.

## Purpose

The purpose of this cluster is to provide a local development and testing environment for the Rosetta API services. It allows developers to deploy and test their services in a controlled environment with monitoring capabilities.

## What It Does

- Sets up a Minikube cluster with a specified profile.
- Installs Prometheus, cAdvisor, and Grafana for monitoring.
- Deploys the Rosetta API services using Helm charts.
- Optionally loads local Docker images for the services.
- Forwards ports for Prometheus, Grafana, and the Rosetta API services.

## Tools

### Minikube

Minikube is a tool that runs a single-node Kubernetes cluster on your local machine. It is useful for development and testing purposes.

### Prometheus

Prometheus is an open-source monitoring and alerting toolkit. It is used to collect and store metrics from various sources, including applications and infrastructure.

### cAdvisor

cAdvisor (Container Advisor) is an open-source container resource usage and performance analysis agent. It provides insights into the resource usage and performance characteristics of running containers.

### Grafana

Grafana is an open-source platform for monitoring and observability. It provides a web-based interface for visualizing and analyzing metrics collected by Prometheus and other data sources.

## Usage

### Prerequisites

The `deploy.sh` script eventually uses Docker, Minikube, Kubectl and Helm, but fear not, it will assist you in installing those if it detects they are absent.
It was only tested on Ubuntu servers.

WARNING: The script *doesn't* work when run from this repository's dev container (at `./ci/container/`).

## Deploying Prod Images

To create and set-up the local cluster and install the production containers for ICP-Rosetta and ICRC1-Rosetta pointing at DFINITY's test ledgers, navigate to this directory and run:
```bash
cd rs/rosetta-api/local/cluster
./deploy.sh [options]
```

**Important:** The script must be run from the `cluster` directory so Helm can properly package the chart files.

You can make the rosetta nodes point to other ledgers by using these flags:
- `--icp-ledger <ledger_id>`: Set the ICP Ledger ID (default: `xafvr-biaaa-aaaai-aql5q-cai`). If `prod`, will point to the official ICP ledger.
- `--icp-symbol <symbol>`: Set the ICP token symbol (default: `TESTICP`).
- `--icrc1-ledgers <ledger_ids>`: Set the ICRC1 Ledger IDs, comma-separated for multiple ledgers (default: `3jkp5-oyaaa-aaaaj-azwqa-cai`). Example: `--icrc1-ledgers 'ledger1-id,ledger2-id,ledger3-id'`.
- `--no-icp-latest`: Skip deploying the ICP Rosetta latest image from Docker Hub (useful when you only want to deploy your local build).
- `--no-icrc1-latest`: Skip deploying the ICRC1 Rosetta latest image from Docker Hub (useful when you only want to deploy your local build).
- `--sqlite-cache-kb <size>`: Set the SQLite cache size in KB (optional, no default). Lower values reduce memory usage but may impact performance. Adjust based on the number of ledgers and available pod memory.
- `--flush-cache-shrink-mem`: Flush the cache and shrink the memory after updating balances. If this flag is present, the feature is enabled; otherwise, it remains disabled.
- `--balance-sync-batch-size <size>`: Set the balance synchronization batch size in blocks (default: `100000`).

ATTENTION: The first run might take a few minutes to finish as it'll create the cluster and install the necessary charts in it. After that, all the script will do is re-deploy the rosetta images with different configuration if needed.

## Deploying Local Images

### Build the local containers
In order to build rosetta containers with local changes, you need to do it from inside the dev container:

```bash
$ ./ci/container/container-run.sh

# Build the TAR file target
$ bazel build //rs/rosetta-api/icp:rosetta_image.tar

# Move the resulting TAR file to a place that can be accessed outside the dev container
$ mv bazel-bin/rs/rosetta-api/icp/rosetta_image.tar /tmp

# Same for ICRC1
$ bazel build //rs/rosetta-api/icrc1:icrc_rosetta_image.tar
$ mv bazel-bin/rs/rosetta-api/icrc1/icrc_rosetta_image.tar /tmp

# Exit the dev container
$ exit
```

### Deploy the local containers

You can use the following flags to deploy additional containers with the TAR files generated above:

- `--local-icp-image-tar <path>`: Path to local ICP image tar file.
- `--local-icrc1-image-tar <path>`: Path to local ICRC1 image tar file.

Example that deploys local versions for both:

```bash
./deploy.sh --local-icp-image-tar /tmp/rosetta_image.tar --local-icrc1-image-tar /tmp/icrc_rosetta_image.tar
```

Example that deploys local ICRC1 Rosetta with multiple ledgers:

```bash
./deploy.sh --local-icrc1-image-tar ~/workspaces/ic/ic-master/bazel-bin/rs/rosetta-api/icrc1/icrc_rosetta_image.tar --icrc1-ledgers 'lkwrt-vyaaa-aaaaq-aadhq-cai,xsi2v-cyaaa-aaaaq-aabfq-cai'
```

Example that deploys **only** your local ICRC1 Rosetta build (skipping the latest image):

```bash
./deploy.sh --local-icrc1-image-tar ~/workspaces/ic/ic-master/bazel-bin/rs/rosetta-api/icrc1/icrc_rosetta_image.tar --icrc1-ledgers 'lkwrt-vyaaa-aaaaq-aadhq-cai,xsi2v-cyaaa-aaaaq-aabfq-cai' --no-icrc1-latest
```

The services and pods deployed with those images will have a `-local` in their names.

### Deploying Only Local or Latest Versions

By default, the script deploys both the latest Docker Hub images and your local builds (if provided). You can use the
`--no-*-latest` flags to skip the latest images:

Example that only deploys the local ICRC1 Rosetta build (no latest ICRC1 Rosetta, no ICP Rosetta)

```bash
./deploy.sh --local-icrc1-image-tar /path/to/image.tar --no-icrc1-latest
```

Example that only deploys the local ICP Rosetta build (no latest ICP Rosetta, no ICRC1 Rosetta)

```bash
./deploy.sh --local-icp-image-tar /path/to/icp.tar --local-icrc1-image-tar /path/to/icrc1.tar --no-icp-latest --no-icrc1-latest
```

### Cleaning up

You can add the `--clean` flag to any usage of `./deploy.sh`. That will wipe out the current cluster and install it from scratch.

For example, the following command installs all prod and local images in a clean cluster:

```bash
./deploy.sh --local-icp-image-tar /tmp/rosetta_image.tar --local-icrc1-image-tar /tmp/icrc_rosetta_image.tar --clean
```

## Monitoring with Grafana

Grafana will run on port 3000. If you're running this in a remote devenv, you'll need to forward your local machine port to your devenv's one in order to access the service from your browser.

The first time you open `http://localhost:3000`, you'll be asked for login credentials. Use `admin` for both username and password. You'll be asked to change the password, you can either do so or just skip, it doesn't matter.

Once in Grafana, import a new dashboard. As an option to import, you'll see a text box to input a json file. Copy and paste the contents of the `rosetta_load_dashboard.json` file in this directory.

Services and pods with suffix `-latest` represent jobs running with the prod images while the ones with suffix `-local` are the ones running with the locally built ones.

## Memory Configuration and Tuning

ICRC Rosetta uses SQLite for each ledger's blockchain data storage. When running multiple ledgers, memory usage can increase significantly. The deployment includes several memory optimizations:

### Default Settings

- Pod memory limit: `1024Mi`
- Pod memory request: `512Mi`
- SQLite cache per database: `20MB` (20480 KB)

## Notes
- The script will automatically install Minikube if they are not found.
- The script uses a dedicated Minikube profile (`local-rosetta`) to avoid conflicts with other Minikube clusters.
