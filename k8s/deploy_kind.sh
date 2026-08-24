#!/usr/bin/env bash
# ==============================================================================
# NetShield AI - Automated Kubernetes (KinD) Deployment Script for Linux / macOS
# ==============================================================================

set -euo pipefail

CLUSTER_NAME="netshield-cluster"

echo "=========================================================="
echo "  NetShield AI - Automated Kubernetes (KinD) Deployment"
echo "=========================================================="

# 1. Check Prerequisites
command -v kind >/dev/null 2>&1 || { echo >&2 "[Error] 'kind' CLI is required. Install from https://kind.sigs.k8s.io"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "[Error] 'kubectl' CLI is required. Install from https://kubernetes.io"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo >&2 "[Error] 'docker' is required and must be running."; exit 1; }

# 2. Create KinD cluster if needed
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
  echo "[KinD] Cluster '${CLUSTER_NAME}' already exists."
else
  echo "[KinD] Creating cluster '${CLUSTER_NAME}' with k8s/kind-config.yaml..."
  kind create cluster --name "${CLUSTER_NAME}" --config k8s/kind-config.yaml
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# 3. Build Docker image
echo "[Docker] Building netshield-ai:latest image..."
docker build -t netshield-ai:latest .

# 4. Load image into KinD cluster nodes
echo "[KinD] Loading docker image into cluster..."
kind load docker-image netshield-ai:latest --name "${CLUSTER_NAME}"

# 5. Deploy NGINX Ingress Controller for KinD
echo "[Ingress] Ensuring NGINX Ingress Controller is deployed..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# 6. Apply NetShield Manifests
echo "[Kubernetes] Applying manifests..."
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml

# 7. Wait for Rollout
echo "[Kubernetes] Waiting for deployment rollout..."
kubectl rollout status deployment/netshield-deployment --timeout=120s

echo "=========================================================="
echo "  NetShield AI Successfully Deployed to KinD Cluster!"
echo "=========================================================="
echo "  Web Dashboard / API:   http://localhost:8000"
echo "  Ingress Gateway:       http://localhost"
echo "  Prometheus Metrics:    http://localhost:8000/metrics"
echo "=========================================================="
