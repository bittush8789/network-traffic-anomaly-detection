# ==============================================================================
# NetShield AI - Automated Kubernetes (KinD) Deployment Script for Windows
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  NetShield AI - Automated Kubernetes (KinD) Deployment" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Prerequisites
if (-not (Get-Command kind -ErrorAction SilentlyContinue)) {
    Write-Host "[Error] 'kind' CLI is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install KinD from: https://kind.sigs.k8s.io/docs/user/quick-start/" -ForegroundColor Yellow
    exit 1
}

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Host "[Error] 'kubectl' is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install kubectl from: https://kubernetes.io/docs/tasks/tools/" -ForegroundColor Yellow
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[Error] 'docker' is not running." -ForegroundColor Red
    exit 1
}

$CLUSTER_NAME = "netshield-cluster"

# 2. Check if cluster exists, otherwise create it
$existingClusters = kind get clusters
if ($existingClusters -contains $CLUSTER_NAME) {
    Write-Host "[KinD] Cluster '$CLUSTER_NAME' already exists." -ForegroundColor Green
} else {
    Write-Host "[KinD] Creating cluster '$CLUSTER_NAME' with k8s/kind-config.yaml..." -ForegroundColor Cyan
    kind create cluster --name $CLUSTER_NAME --config k8s/kind-config.yaml
}

# Set kubectl context
kubectl config use-context "kind-$CLUSTER_NAME"

# 3. Build Docker image
Write-Host "[Docker] Building netshield-ai:latest image..." -ForegroundColor Cyan
docker build -t netshield-ai:latest .

# 4. Load image into KinD cluster nodes
Write-Host "[KinD] Loading docker image into cluster nodes..." -ForegroundColor Cyan
kind load docker-image netshield-ai:latest --name $CLUSTER_NAME

# 5. Install NGINX Ingress Controller (if not installed)
Write-Host "[Ingress] Ensuring NGINX Ingress Controller is deployed..." -ForegroundColor Cyan
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# 6. Apply NetShield Kubernetes Manifests
Write-Host "[Kubernetes] Applying NetShield manifests..." -ForegroundColor Cyan
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml

# 7. Wait for Rollout
Write-Host "[Kubernetes] Waiting for deployment rollout..." -ForegroundColor Cyan
kubectl rollout status deployment/netshield-deployment --timeout=120s

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  NetShield AI Successfully Deployed to KinD Cluster!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Web Dashboard / API:   http://localhost:8000" -ForegroundColor White
Write-Host "  Ingress Gateway:       http://localhost" -ForegroundColor White
Write-Host "  Prometheus Metrics:    http://localhost:8000/metrics" -ForegroundColor White
Write-Host "  NodePort Access:       http://localhost:30080" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
