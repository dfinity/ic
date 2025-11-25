#!/bin/bash

set -e

# Usage: deploy.sh [options]
# Options:
#   --icp-ledger <ledger_id>         Set the ICP Ledger ID (default: xafvr-biaaa-aaaai-aql5q-cai)
#   --icp-symbol <symbol>            Set the ICP token symbol (default: TESTICP)
#   --icrc1-ledgers <ledger_ids>     Set the ICRC1 Ledger IDs, comma-separated for multiple ledgers (default: 3jkp5-oyaaa-aaaaj-azwqa-cai)
#   --sqlite-cache-kb <size>         SQLite cache size in KB (optional, no default)
#   --flush-cache-shrink-mem         Flush the database cache and shrink the memory after updating account balances
#   --local-icp-image-tar <path>     Path to local ICP image tar file
#   --local-icrc1-image-tar <path>   Path to local ICRC1 image tar file
#   --no-icp-latest                  Don't deploy ICP Rosetta latest image
#   --no-icrc1-latest                Don't deploy ICRC1 Rosetta latest image
#   --external-ports                 Forward external connections to TCP/3000 (Grafana), TCP/8080 (ICP) and TCP/8888 (ICRC) for latest Rosetta instances
#   --clean                          Clean up Minikube cluster and Helm chart before deploying
#   --stop                           Stop the Minikube cluster
#   --help                           Display this help message

# Default values
ICP_LEDGER="xafvr-biaaa-aaaai-aql5q-cai"
ICP_SYMBOL="TESTICP"
ICRC1_LEDGER="3jkp5-oyaaa-aaaaj-azwqa-cai"
SQLITE_CACHE_KB=""
FLUSH_CACHE_SHRINK_MEM=false
LOCAL_ICP_IMAGE_TAR=""
LOCAL_ICRC1_IMAGE_TAR=""
DEPLOY_ICP_LATEST=true
DEPLOY_ICRC1_LATEST=true
EXTERNAL_PORTS=false
CLEAN=false
STOP=false
MINIKUBE_PROFILE="local-rosetta"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --icp-ledger)
            ICP_LEDGER="$2"
            shift
            ;;
        --icp-symbol)
            ICP_SYMBOL="$2"
            shift
            ;;
        --icrc1-ledgers)
            ICRC1_LEDGER="$2"
            shift
            ;;
        --sqlite-cache-kb)
            SQLITE_CACHE_KB="$2"
            shift
            ;;
        --flush-cache-shrink-mem)
            FLUSH_CACHE_SHRINK_MEM=true
            ;;
        --local-icp-image-tar)
            LOCAL_ICP_IMAGE_TAR="$2"
            shift
            ;;
        --local-icrc1-image-tar)
            LOCAL_ICRC1_IMAGE_TAR="$2"
            shift
            ;;
        --no-icp-latest)
            DEPLOY_ICP_LATEST=false
            ;;
        --no-icrc1-latest)
            DEPLOY_ICRC1_LATEST=false
            ;;
        --external-ports)
            EXTERNAL_PORTS=true
            ;;
        --clean) CLEAN=true ;;
        --stop) STOP=true ;;
        --help)
            sed -n '5,19p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown parameter passed: $1"
            exit 1
            ;;
    esac
    shift
done

# Function that waits for a resource to be ready
wait_for_ready() {
    local resource_type="$1"  # The type of the resource (e.g., pod, deployment)
    local resource_label="$2" # The label of the resource
    local namespace="$3"      # The namespace of the resource (optional, defaults to 'default')
    local timeout=$4          # Timeout in seconds

    # Default namespace if not provided
    namespace="${namespace:-default}"

    # wait 2 seconds
    sleep 2

    kubectl wait --namespace $namespace --for=condition=Ready $resource_type -l $resource_label --timeout=${timeout}s --context="$MINIKUBE_PROFILE"
}

# Stop Minikube cluster if --stop flag is set
[[ "$STOP" == true ]] && {
    echo "Stopping Minikube cluster..."
    minikube stop -p "$MINIKUBE_PROFILE"
    exit 0
}

# Set default values for prod
[[ "$ICP_LEDGER" == "prod" ]] && ICP_LEDGER="ryjl3-tyaaa-aaaaa-aaaba-cai" && ICP_SYMBOL="ICP"

# Ensure Docker is installed
command -v docker &>/dev/null || {
    read -p "Docker not found, do you want to install Docker? (y/n): " install_docker
    if [[ "$install_docker" == "y" ]]; then
        echo "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
    else
        echo "Docker is required. Exiting..."
        exit 1
    fi
}

# Ensure Docker is running
docker info &>/dev/null || {
    echo "Docker is not running. Please start Docker and try again."
    echo "Usually that can be done with "sudo systemctl start docker" or "sudo service docker start""
    exit 1
}

# Ensure kubectl is installed
command -v kubectl &>/dev/null || {
    read -p "kubectl not found, do you want to install kubectl? (y/n): " install_kubectl
    if [[ "$install_kubectl" == "y" ]]; then
        echo "Installing kubectl..."
        curl -LO "https://dl.k8s.io/release/v1.31.5/bin/linux/amd64/kubectl"
        chmod +x kubectl
        sudo mv kubectl /usr/local/bin/
    else
        echo "kubectl is required. Exiting..."
        exit 1
    fi
}

# Ensure Minikube is installed
command -v minikube &>/dev/null || {
    read -p "Minikube not found, do you want to install Minikube? (y/n): " install_minikube
    if [[ "$install_minikube" == "y" ]]; then
        echo "Installing Minikube..."
        curl -Lo minikube https://storage.googleapis.com/minikube/releases/v1.34.0/minikube-linux-amd64
        chmod +x minikube
        sudo mv minikube /usr/local/bin/
    else
        echo "Minikube is required. Exiting..."
        exit 1
    fi
}

# Ensure Helm is installed
command -v helm &>/dev/null || {
    read -p "Helm not found, do you want to install Helm? (y/n): " install_helm
    if [[ "$install_helm" == "y" ]]; then
        echo "Installing Helm..."
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    else
        echo "Helm is required. Exiting..."
        exit 1
    fi
}

# Clean up Minikube cluster and Helm chart if --clean flag is set
[[ "$CLEAN" == true ]] && {
    echo "Cleaning up Minikube cluster and Helm chart..."
    helm uninstall local-rosetta || true
    minikube delete -p "$MINIKUBE_PROFILE"
}

# Start Minikube with the specified profile if not already running
minikube status -p "$MINIKUBE_PROFILE" &>/dev/null || {
    echo "Starting Minikube with profile $MINIKUBE_PROFILE..."
    minikube start -p "$MINIKUBE_PROFILE"
}

# Add Helm repositories and update
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add ckotzbauer https://ckotzbauer.github.io/helm-charts
helm repo update

# Function to check if a port forward exists and create it if not
port_forward() {
    local namespace=$1
    local svc=$2
    local port=$3
    pgrep -f "kubectl port-forward -n $namespace svc/$svc $port --context=$MINIKUBE_PROFILE" &>/dev/null || {
        echo "Forwarding $svc port..."
        kubectl port-forward -n $namespace svc/$svc $port --context="$MINIKUBE_PROFILE" &>/dev/null &
    }
}

# Install or upgrade cAdvisor
helm list -n monitoring --kube-context="$MINIKUBE_PROFILE" | grep -q cadvisor || {
    echo "Installing cAdvisor..."
    helm install cadvisor ckotzbauer/cadvisor --namespace monitoring --create-namespace --kube-context="$MINIKUBE_PROFILE"
}

# Wait for cAdvisor server to be ready
echo "Waiting for cAdvisor server to be ready..."
wait_for_ready pod app.kubernetes.io/name=cadvisor monitoring 300

# Install or upgrade kube-prometheus-stack (includes Prometheus, Grafana, Alertmanager, Node Exporter, etc.)
helm list -n monitoring --kube-context="$MINIKUBE_PROFILE" | grep -q kube-prometheus || {
    echo "Installing kube-prometheus-stack..."
    helm install kube-prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --create-namespace \
        --values kube-prometheus-values.yaml \
        --kube-context="$MINIKUBE_PROFILE"
}

# Wait for kube-prometheus-stack operator to be ready first
echo "Waiting for kube-prometheus-stack operator to be ready..."
wait_for_ready pod app=kube-prometheus-stack-operator monitoring 300

# Wait for Prometheus to be ready
echo "Waiting for Prometheus to be ready..."
wait_for_ready pod app.kubernetes.io/name=prometheus monitoring 300

# Forward Prometheus port if not already forwarded
port_forward monitoring kube-prometheus-kube-prome-prometheus 9090:9090

# Function to load a local TAR if provided
load_local_tar() {
    local tar_path=$1
    [[ -n "$tar_path" ]] && {
        echo "Loading local image into Minikube..."
        eval $(minikube -p "$MINIKUBE_PROFILE" docker-env)
        docker load -i "$tar_path"
        eval $(minikube -p "$MINIKUBE_PROFILE" docker-env -u)
    }
    return 0
}

# Load local ICP and ICRC1 images if provided
load_local_tar "$LOCAL_ICP_IMAGE_TAR"
load_local_tar "$LOCAL_ICRC1_IMAGE_TAR"

echo "Deploying Helm chart..."
# Deploy or upgrade the Helm chart
# Escape commas in ICRC1_LEDGER for Helm (commas are interpreted as value separators)
ESCAPED_ICRC1_LEDGER="${ICRC1_LEDGER//,/\\,}"

# Build helm command with conditional parameters
HELM_CMD=(helm upgrade --install local-rosetta .
    --set icpConfig.canisterId="$ICP_LEDGER"
    --set icpConfig.tokenSymbol="$ICP_SYMBOL"
    --set icpConfig.deployLatest="$DEPLOY_ICP_LATEST"
    --set-string icrcConfig.ledgerId="$ESCAPED_ICRC1_LEDGER"
    --set icrcConfig.deployLatest="$DEPLOY_ICRC1_LATEST"
    --set icpConfig.useLocallyBuilt=$([[ -n "$LOCAL_ICP_IMAGE_TAR" ]] && echo "true" || echo "false")
    --set icrcConfig.useLocallyBuilt=$([[ -n "$LOCAL_ICRC1_IMAGE_TAR" ]] && echo "true" || echo "false")
    --kube-context="$MINIKUBE_PROFILE"
)

# Add optional sqlite-cache-kb parameter only if specified
[[ -n "$SQLITE_CACHE_KB" ]] && HELM_CMD+=(--set icrcConfig.sqliteCacheKb="$SQLITE_CACHE_KB")

# Add flush-cache-shrink-mem parameter
HELM_CMD+=(--set icrcConfig.flushCacheShrinkMem="$FLUSH_CACHE_SHRINK_MEM")

# Execute the helm command
"${HELM_CMD[@]}"

# Wait for Grafana server to be ready
echo "Waiting for Grafana server to be ready..."
wait_for_ready pod app.kubernetes.io/name=grafana monitoring 300

# Forward Grafana port if not already forwarded (skip if external-ports is enabled, as it will be handled later)
if [[ "$EXTERNAL_PORTS" != true ]]; then
    port_forward monitoring kube-prometheus-grafana 3000:80
fi

# Function to check if a service exists and print its URL
print_service_url() {
    local namespace=$1
    local service=$2
    if kubectl get -n "$namespace" svc "$service" --context="$MINIKUBE_PROFILE" &>/dev/null; then
        local nodePort=$(kubectl get -n "$namespace" svc "$service" -o jsonpath='{.spec.ports[0].nodePort}' --context="$MINIKUBE_PROFILE")
        echo "$service: http://localhost:$nodePort"
    else
        echo "$service is not present."
    fi
}

# Wait for the rosetta services to be ready and forward the ports
for service in icp-rosetta-local icp-rosetta-latest icrc-rosetta-local icrc-rosetta-latest; do
    if kubectl get -n rosetta-api svc "$service" --context="$MINIKUBE_PROFILE" &>/dev/null; then
        echo "Waiting for $service server to be ready..."
        wait_for_ready pod app="$service" rosetta-api 300

        # Find the nodeport for the service
        nodePort=$(kubectl get -n rosetta-api svc "$service" -o jsonpath='{.spec.ports[0].nodePort}' --context="$MINIKUBE_PROFILE")

        echo "Forwarding $service port to http://localhost:$nodePort..."

        # Forward the port if it is not already forwarded
        port_forward rosetta-api "$service" "$nodePort:3000"
    fi
done

# Kill any existing external port forwards on 3000, 8080 and 8888 if they exist
if pgrep -f "kubectl port-forward.*--address 0.0.0.0.*3000:80" &>/dev/null \
    || pgrep -f "kubectl port-forward.*--address 0.0.0.0.*8080:3000" &>/dev/null \
    || pgrep -f "kubectl port-forward.*--address 0.0.0.0.*8888:3000" &>/dev/null; then
    echo ""
    echo "Cleaning up external port forwards (3000, 8080, 8888)..."
    pkill -f "kubectl port-forward.*--address 0.0.0.0.*3000:80" 2>/dev/null || true
    pkill -f "kubectl port-forward.*--address 0.0.0.0.*8080:3000" 2>/dev/null || true
    pkill -f "kubectl port-forward.*--address 0.0.0.0.*8888:3000" 2>/dev/null || true
    echo "External port forwards removed."
fi

# Set up external port forwarding if --external-ports flag is set
if [[ "$EXTERNAL_PORTS" == true ]]; then
    echo ""
    echo "Setting up external port forwarding..."

    # Kill any localhost-only Grafana forward on port 3000 (to avoid conflicts)
    pkill -f "kubectl port-forward.*-n monitoring svc/kube-prometheus-grafana 3000:80.*--context=$MINIKUBE_PROFILE" 2>/dev/null || true

    # Forward ICP Rosetta to external port 8080
    if kubectl get -n rosetta-api svc icp-rosetta-latest --context="$MINIKUBE_PROFILE" &>/dev/null; then
        echo "Forwarding icp-rosetta-latest to 0.0.0.0:8080..."
        kubectl port-forward --address 0.0.0.0 -n rosetta-api svc/icp-rosetta-latest 8080:3000 --context="$MINIKUBE_PROFILE" &>/dev/null &
        sleep 1
    fi

    # Forward ICRC Rosetta to external port 8888
    if kubectl get -n rosetta-api svc icrc-rosetta-latest --context="$MINIKUBE_PROFILE" &>/dev/null; then
        echo "Forwarding icrc-rosetta-latest to 0.0.0.0:8888..."
        kubectl port-forward --address 0.0.0.0 -n rosetta-api svc/icrc-rosetta-latest 8888:3000 --context="$MINIKUBE_PROFILE" &>/dev/null &
        sleep 1
    fi

    # Forward Grafana to external port 3000
    if kubectl get -n monitoring svc kube-prometheus-grafana --context="$MINIKUBE_PROFILE" &>/dev/null; then
        echo "Forwarding Grafana to 0.0.0.0:3000..."
        kubectl port-forward --address 0.0.0.0 -n monitoring svc/kube-prometheus-grafana 3000:80 --context="$MINIKUBE_PROFILE" &>/dev/null &
        sleep 1
    fi
fi

# Print the URLs
echo ""
echo "************************************"
echo "Deployment complete. Access the services at the following URLs:"
print_service_url rosetta-api icp-rosetta-local
print_service_url rosetta-api icp-rosetta-latest
print_service_url rosetta-api icrc-rosetta-local
print_service_url rosetta-api icrc-rosetta-latest
echo "Prometheus: http://localhost:9090"
echo "Grafana: http://localhost:3000"

if [[ "$EXTERNAL_PORTS" == true ]]; then
    echo ""
    echo "External access enabled:"
    echo "  ICP Rosetta:  <your-hostname>:8080"
    echo "  ICRC Rosetta: <your-hostname>:8888"
    echo "  Grafana:      <your-hostname>:3000"
fi

echo "************************************"
