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

To create and set-up the local cluster and install the production containers for ICP-Rosetta and ICRC1-Rosetta pointing at DFINITY's test ledgers, simply do:
```bash
./deploy.sh [options]
```

You can make the rosetta nodes point to other ledgers by using these flags:
- `--icp-ledger <ledger_id>`: Set the ICP Ledger ID (default: `xafvr-biaaa-aaaai-aql5q-cai`). If `prod`, will point to the official ICP ledger.
- `--icp-symbol <symbol>`: Set the ICP token symbol (default: `TESTICP`).
- `--icrc1-ledger <ledger_id>`: Set the ICRC1 Ledger ID (default: `3jkp5-oyaaa-aaaaj-azwqa-cai`).

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

The services and pods deployed with those images will have a `-local` in their names.


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


## Notes
- The script will automatically install Minikube if they are not found.
- The script uses a dedicated Minikube profile (`local-rosetta`) to avoid conflicts with other Minikube clusters.
