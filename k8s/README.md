# ☸️ NetShield AI — Production Kubernetes & KServe Guide

This directory contains production-ready **Kubernetes (K8s)** manifests, a **KinD (Kubernetes in Docker)** local multi-node configuration, auto-scaling rules (**HPA**), and **KServe InferenceService** model-serving descriptors for **NetShield AI**.

---

## 📁 Kubernetes Files in `k8s/`

| File | Purpose |
|---|---|
| [`serviceaccount.yaml`](serviceaccount.yaml) | Dedicated `ServiceAccount` (`netshield-sa`), `Role`, and `RoleBinding` for pod RBAC. |
| [`kind-config.yaml`](kind-config.yaml) | 3-node KinD cluster (1 control-plane, 2 workers) with ingress port mapping (`80`, `443`, `8000`, `9090`). |
| [`deployment.yaml`](deployment.yaml) | High-availability Deployment (`replicas: 2`, RollingUpdate, CPU/Memory limits, Liveness & Readiness probes, `serviceAccountName`). |
| [`service.yaml`](service.yaml) | `ClusterIP` service (port 80) and `NodePort` service (port 30080 $\rightarrow$ host 8000). |
| [`ingress.yaml`](ingress.yaml) | NGINX Ingress controller rules with timeout & body size settings. |
| [`pvc.yaml`](pvc.yaml) | PersistentVolumeClaim (`netshield-storage-pvc`) for SQLite database, models, and MLflow data. |
| [`configmap.yaml`](configmap.yaml) | Production environment configuration. |
| [`hpa.yaml`](hpa.yaml) | Horizontal Pod Autoscaler ($2$ to $10$ pods based on $70\%$ CPU utilization). |
| [`deploy_kind.ps1`](deploy_kind.ps1) | Automated deployment script for Windows PowerShell. |
| [`deploy_kind.sh`](deploy_kind.sh) | Automated deployment script for Linux/macOS. |

> 💡 **Looking for KServe ML Serving?** See the dedicated [`kserve/`](../kserve/) folder.

---

## 🚀 Quickstart: Deploy to Local KinD Cluster

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/) running.
- [KinD CLI](https://kind.sigs.k8s.io/docs/user/quick-start/) (`kind` in PATH).
- [kubectl CLI](https://kubernetes.io/docs/tasks/tools/) (`kubectl` in PATH).

### 2. Automated One-Command Deployment

**Windows PowerShell:**
```powershell
.\k8s\deploy_kind.ps1
```

**Linux / macOS (Bash):**
```bash
chmod +x k8s/deploy_kind.sh
./k8s/deploy_kind.sh
```

---

### 3. Manual Step-by-Step Deployment

```bash
# 1. Create multi-node cluster
kind create cluster --name netshield-cluster --config k8s/kind-config.yaml

# 2. Build local docker image
docker build -t netshield-ai:latest .

# 3. Load image into KinD cluster
kind load docker-image netshield-ai:latest --name netshield-cluster

# 4. Install NGINX Ingress Controller for KinD
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# 5. Apply all manifests
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml

# 6. Verify pods and rollout
kubectl get pods -l app=netshield-ai
kubectl rollout status deployment/netshield-deployment
```

---

## 🤖 Deploying with KServe (ML Model Serving)

To deploy the Isolation Forest model using **KServe** for high-throughput, autoscaling ML serving:

### 1. Install KServe & Knative Prerequisites on your Cluster:
```bash
# Install Cert-Manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Install Knative Serving
kubectl apply -f https://github.com/knative/serving/releases/download/knative-v1.11.0/serving-core.yaml

# Install KServe Operator
kubectl apply -f https://github.com/kserve/kserve/releases/download/v0.11.2/kserve.yaml
```

### 2. Apply KServe InferenceService Manifest:
```bash
kubectl apply -f k8s/kserve-inferenceservice.yaml
```

### 3. Check InferenceService Status:
```bash
kubectl get inferenceservices netshield-anomaly-detector
```

---

## 🔍 Verification & Debugging

```bash
# Check Pod status
kubectl get pods -l app=netshield-ai -o wide

# View Application Logs
kubectl logs -f deployment/netshield-deployment

# Check Horizontal Pod Autoscaler (HPA)
kubectl get hpa netshield-hpa

# Check Ingress Routing
kubectl get ingress netshield-ingress
```

### Access URLs:
- **NetShield Web Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Ingress Gateway**: [http://localhost](http://localhost)
- **Prometheus Metrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
