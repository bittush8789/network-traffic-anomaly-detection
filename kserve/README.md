# 🤖 KServe ML Inference Deployment for NetShield AI

This directory contains the dedicated **KServe** model-serving configuration for **NetShield AI**, enabling high-throughput, low-latency, and auto-scaling model serving using the standard **Open Inference Protocol (v2)**.

---

## 📁 Files in `kserve/`

| File | Description |
|---|---|
| [`serviceaccount.yaml`](serviceaccount.yaml) | Dedicated `ServiceAccount` (`kserve-model-sa`) with RBAC permissions for model and PVC access. |
| [`inferenceservice.yaml`](inferenceservice.yaml) | KServe `InferenceService` custom resource (v1beta1) configuring the Scikit-learn predictor, resource limits, and Knative auto-scaling. |
| [`sample-request.json`](sample-request.json) | Example v2 protocol payload for testing raw model predictions. |

---

## 🚀 How to Deploy with KServe

### 1. Prerequisites (Install KServe & Knative on Cluster)
```bash
# 1. Install Cert-Manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# 2. Install Knative Serving
kubectl apply -f https://github.com/knative/serving/releases/download/knative-v1.11.0/serving-core.yaml

# 3. Install KServe Operator
kubectl apply -f https://github.com/kserve/kserve/releases/download/v0.11.2/kserve.yaml
```

### 2. Apply ServiceAccount & InferenceService
```bash
# 1. Apply dedicated service account & RBAC
kubectl apply -f kserve/serviceaccount.yaml

# 2. Deploy the InferenceService
kubectl apply -f kserve/inferenceservice.yaml
```

### 3. Check Deployment Status
```bash
# Check status of InferenceService
kubectl get inferenceservice netshield-anomaly-detector

# View predictor pod logs
kubectl logs -l serving.kserve.io/inferenceservice=netshield-anomaly-detector -c kserve-container
```

---

## 🧪 Testing KServe Predictions (v2 Protocol)

When the InferenceService is ready (`READY=True`), get the service URL and send a prediction request:

```bash
# Get Inference URL
export INFERENCE_URL=$(kubectl get inferenceservice netshield-anomaly-detector -o jsonpath='{.status.url}')

# Send test prediction request
curl -v -X POST "${INFERENCE_URL}/v2/models/netshield-anomaly-detector/infer" \
  -H "Content-Type: application/json" \
  -d @kserve/sample-request.json
```
