Testnet on K8s
---

POC deployment of 2 node TestNet.

# Requirements

TestNet requires dedicated `IPReservation`.  
K8s cluster users `fda6:8d22:43e1::/48` for `Pod` subnet so some subnet of that needs to be reserved.  
Defined variables for `IPReservation`, K8s namespace and TestNet name.

```bash
export CIDR_RESERVATION="fda6:8d22:43e1:fda6::/64"
export CIDR_PREFIX="fda6:8d22:43e1:fda6::"
export NAMESPACE="team-node"
export NAME="tnet"
```

# Deployment

```bash
# Create TestNet $NAME from version 2393534478f4fea77e8790ddd07fc0689c5a25fc

./k8s_testnet.sh $NAME 2393534478f4fea77e8790ddd07fc0689c5a25fc
```

# Cleaning

```bash
# Delete TestNet $NAME

./k8s_clean.sh $NAME
```
