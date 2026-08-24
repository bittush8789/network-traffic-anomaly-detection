"""
FastAPI Backend Application for Network Traffic Anomaly Detection.
Provides REST APIs for prediction, training, analytics, Prometheus metrics, and frontend hosting.
"""
import io
import os
import time
from typing import List, Dict, Any, Optional
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from backend.database import (
    BASE_DIR,
    init_db,
    get_db,
    save_traffic_records,
    get_traffic_records,
    get_traffic_stats,
    get_timeline_data,
    save_training_run,
    get_training_runs,
    clear_database,
    Session,
)
from backend.ml import (
    detector_instance,
    MLflowTracker,
    SyntheticTrafficGenerator,
    DATA_DIR,
    MODEL_FILE,
)

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB
    init_db()

    # Initialize baseline dataset & model if not existing
    csv_path = os.path.join(DATA_DIR, "network_traffic.csv")
    if not os.path.exists(csv_path):
        print("[Startup] Generating initial synthetic network traffic dataset...")
        generator = SyntheticTrafficGenerator()
        df = generator.generate_dataset(num_samples=2500, anomaly_ratio=0.07)
        df.to_csv(csv_path, index=False)

    if not os.path.exists(MODEL_FILE):
        print("[Startup] Training initial Isolation Forest model...")
        df = pd.read_csv(csv_path)
        stats = detector_instance.train(df)
        run_id = MLflowTracker.log_training_run(detector_instance, stats, df)
        save_training_run({
            "model_name": "IsolationForest",
            "n_estimators": detector_instance.n_estimators,
            "contamination": detector_instance.contamination,
            "num_samples": stats["num_samples"],
            "num_anomalies_detected": stats["num_anomalies"],
            "anomaly_rate_pct": stats["anomaly_rate_pct"],
            "mlflow_run_id": run_id,
            "status": "SUCCESS",
            "notes": "Initial startup baseline model",
        })
    else:
        detector_instance.load()

    # Preload initial dataset to DB if DB is empty
    stats = get_traffic_stats()
    if stats["total_records"] == 0 and os.path.exists(csv_path):
        print("[Startup] Ingesting initial records to SQLite DB...")
        df_init = pd.read_csv(csv_path)
        predictions = detector_instance.predict(df_init)
        save_traffic_records(predictions)

    PROMETHEUS_ACTIVE_MODEL_CONTAMINATION.set(detector_instance.contamination)
    print("[Startup] Network Traffic Anomaly Detection System Ready.")
    yield


# Initialize FastAPI App
app = FastAPI(
    title="Network Traffic Anomaly Detection API",
    description="Machine Learning based real-time network anomaly detection system using Isolation Forest.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus Metrics Definitions
PROMETHEUS_TRAFFIC_TOTAL = Counter(
    "network_traffic_flows_total",
    "Total count of network traffic flows analyzed",
    ["protocol", "severity"],
)
PROMETHEUS_ANOMALIES_TOTAL = Counter(
    "network_anomalies_detected_total",
    "Total number of anomalies detected",
    ["anomaly_type", "severity"],
)
PROMETHEUS_ANOMALY_SCORE_GAUGE = Gauge(
    "network_latest_anomaly_score",
    "Anomaly score of the latest processed flow (0-100)",
)
PROMETHEUS_ACTIVE_MODEL_CONTAMINATION = Gauge(
    "network_model_contamination",
    "Configured contamination factor of active model",
)
PROMETHEUS_INFERENCE_LATENCY = Histogram(
    "network_inference_latency_seconds",
    "Inference latency per prediction batch in seconds",
)


# Pydantic Schemas
class SinglePacketRequest(BaseModel):
    src_ip: str = Field(default="192.168.1.45", description="Source IP address")
    dst_ip: str = Field(default="104.244.42.1", description="Destination IP address")
    protocol: str = Field(default="TCP", description="Protocol: TCP, UDP, ICMP")
    src_port: int = Field(default=49152, description="Source Port")
    dst_port: int = Field(default=443, description="Destination Port")
    packet_count: int = Field(default=12, ge=1, description="Number of packets")
    byte_count: int = Field(default=4200, ge=0, description="Total byte count")
    duration: float = Field(default=0.15, ge=0.0, description="Flow duration in seconds")
    flag: str = Field(default="SF", description="Connection status flag (SF, S0, REJ, RSTO, etc.)")
    failed_connections: int = Field(default=0, ge=0, description="Number of failed attempts")


class TrainRequest(BaseModel):
    n_estimators: int = Field(default=100, ge=10, le=500, description="Number of trees in forest")
    contamination: float = Field(default=0.05, ge=0.001, le=0.30, description="Expected anomaly proportion")
    use_existing_db: bool = Field(default=False, description="Train on historical DB records if true")


class SimulationRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=50, description="Number of flows to simulate")
    force_anomaly: Optional[str] = Field(default=None, description="Optional attack type to inject")


# Prometheus Metrics Endpoint
@app.get("/metrics", tags=["Monitoring"])
def metrics():
    """Exposes Prometheus application and model metrics."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# REST API Endpoints
@app.get("/api/health", tags=["System"])
def health_check():
    """System health check and active model status."""
    if not detector_instance.is_trained:
        detector_instance.load()

    return {
        "status": "healthy",
        "service": "Network Traffic Anomaly Detection API",
        "model_loaded": detector_instance.is_trained,
        "model_params": {
            "n_estimators": detector_instance.n_estimators,
            "contamination": detector_instance.contamination,
            "features_count": len(detector_instance.preprocessor.feature_names),
        },
    }


@app.get("/api/stats", tags=["Analytics"])
def get_stats(db: Session = Depends(get_db)):
    """Summary KPI metrics and aggregate distribution for dashboard."""
    return get_traffic_stats(db=db)


@app.get("/api/timeline", tags=["Analytics"])
def get_timeline(points: int = Query(default=24, ge=5, le=100), db: Session = Depends(get_db)):
    """Time-series anomaly counts and traffic volume for charting."""
    return get_timeline_data(points=points, db=db)


@app.get("/api/logs", tags=["Traffic"])
def get_logs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    protocol: Optional[str] = Query(default=None),
    anomaly_only: bool = Query(default=False),
    search_ip: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Filterable and paginated network traffic logs."""
    return get_traffic_records(
        limit=limit,
        offset=offset,
        severity=severity,
        protocol=protocol,
        anomaly_only=anomaly_only,
        search_ip=search_ip,
        db=db,
    )


@app.post("/api/predict/single", tags=["Inference"])
def predict_single(req: SinglePacketRequest, db: Session = Depends(get_db)):
    """Evaluates a single network packet/flow in real-time."""
    start_time = time.time()
    input_data = pd.DataFrame([req.model_dump()])
    
    with PROMETHEUS_INFERENCE_LATENCY.time():
        predictions = detector_instance.predict(input_data)
        
    result = predictions[0]
    latency_ms = round((time.time() - start_time) * 1000, 2)
    result["latency_ms"] = latency_ms

    # Save to DB
    save_traffic_records([result], db=db)

    # Update Prometheus metrics
    PROMETHEUS_TRAFFIC_TOTAL.labels(protocol=result["protocol"], severity=result["severity"]).inc()
    if result["is_anomaly"]:
        PROMETHEUS_ANOMALIES_TOTAL.labels(anomaly_type=result["anomaly_type"], severity=result["severity"]).inc()
    PROMETHEUS_ANOMALY_SCORE_GAUGE.set(result["anomaly_score"])

    return result


@app.post("/api/predict/batch", tags=["Inference"])
async def predict_batch(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Processes uploaded CSV file of network flows and saves predictions to SQLite."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported.")

    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV file: {str(e)}")

    if df.empty:
        raise HTTPException(status_code=400, detail="Uploaded CSV file is empty.")

    # Run predictions
    with PROMETHEUS_INFERENCE_LATENCY.time():
        results = detector_instance.predict(df)

    # Save batch to SQLite
    saved_count = save_traffic_records(results, db=db)

    # Update Prometheus metrics
    for r in results:
        PROMETHEUS_TRAFFIC_TOTAL.labels(protocol=r.get("protocol", "TCP"), severity=r.get("severity", "Normal")).inc()
        if r.get("is_anomaly"):
            PROMETHEUS_ANOMALIES_TOTAL.labels(anomaly_type=r.get("anomaly_type", "Benign"), severity=r.get("severity", "Normal")).inc()

    anomalies_count = sum(1 for r in results if r.get("is_anomaly"))

    return {
        "status": "success",
        "filename": file.filename,
        "total_records_processed": len(results),
        "anomalies_detected": anomalies_count,
        "anomaly_rate_pct": round(anomalies_count / len(results) * 100.0, 2) if results else 0,
        "saved_to_database": saved_count,
        "sample_preview": results[:10],
    }


@app.post("/api/train", tags=["Model Training"])
def train_model(req: TrainRequest, db: Session = Depends(get_db)):
    """Retrains Isolation Forest model with specified hyperparameters and logs run to MLflow."""
    # Determine training data source
    if req.use_existing_db:
        # Load from DB
        raw_recs = db.query(TrafficRecord).all()
        if len(raw_recs) < 50:
            raise HTTPException(status_code=400, detail="Insufficient records in database for retraining (min 50 required).")
        df_train = pd.DataFrame([r.to_dict() for r in raw_recs])
    else:
        # Load default CSV dataset or synthetic benchmark
        csv_path = os.path.join(DATA_DIR, "network_traffic.csv")
        if os.path.exists(csv_path):
            df_train = pd.read_csv(csv_path)
        else:
            generator = SyntheticTrafficGenerator()
            df_train = generator.generate_dataset(num_samples=3000)
            df_train.to_csv(csv_path, index=False)

    # Configure detector
    detector_instance.n_estimators = req.n_estimators
    detector_instance.contamination = req.contamination

    # Train model
    stats = detector_instance.train(df_train)

    # Log to MLflow
    mlflow_run_id = MLflowTracker.log_training_run(detector_instance, stats, df_train)

    # Save run to SQLite
    run_record = save_training_run({
        "model_name": "IsolationForest",
        "n_estimators": req.n_estimators,
        "contamination": req.contamination,
        "max_samples": "auto",
        "num_samples": stats["num_samples"],
        "num_anomalies_detected": stats["num_anomalies"],
        "anomaly_rate_pct": stats["anomaly_rate_pct"],
        "mlflow_run_id": mlflow_run_id,
        "status": "SUCCESS",
        "notes": f"Trained on {'DB' if req.use_existing_db else 'CSV'} with contamination={req.contamination}",
    }, db=db)

    PROMETHEUS_ACTIVE_MODEL_CONTAMINATION.set(req.contamination)

    return {
        "status": "success",
        "training_stats": stats,
        "mlflow_run_id": mlflow_run_id,
        "run_id": run_record.id,
    }


@app.get("/api/mlflow/runs", tags=["Model Training"])
def list_training_runs(limit: int = Query(default=10, ge=1, le=50), db: Session = Depends(get_db)):
    """Retrieves history of model training runs and MLflow tracking references."""
    return get_training_runs(limit=limit, db=db)


@app.post("/api/simulate/traffic", tags=["Simulation"])
def simulate_traffic(req: SimulationRequest, db: Session = Depends(get_db)):
    """Generates synthetic network flows, analyzes them in real-time, and updates DB & metrics."""
    generator = SyntheticTrafficGenerator()
    flows = [generator.generate_single_flow(force_anomaly_type=req.force_anomaly) for _ in range(req.count)]
    df_flows = pd.DataFrame(flows)

    with PROMETHEUS_INFERENCE_LATENCY.time():
        predictions = detector_instance.predict(df_flows)

    save_traffic_records(predictions, db=db)

    for r in predictions:
        PROMETHEUS_TRAFFIC_TOTAL.labels(protocol=r.get("protocol", "TCP"), severity=r.get("severity", "Normal")).inc()
        if r.get("is_anomaly"):
            PROMETHEUS_ANOMALIES_TOTAL.labels(anomaly_type=r.get("anomaly_type", "Benign"), severity=r.get("severity", "Normal")).inc()
        PROMETHEUS_ANOMALY_SCORE_GAUGE.set(r.get("anomaly_score", 0.0))

    return {
        "status": "success",
        "count": len(predictions),
        "flows": predictions,
    }


@app.delete("/api/data/clear", tags=["System"])
def reset_database(db: Session = Depends(get_db)):
    """Clears all traffic records from database."""
    clear_database(db=db)
    return {"status": "success", "message": "Database records cleared successfully."}


# Mount Static Frontend
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", response_class=HTMLResponse, tags=["Frontend"])
    def serve_dashboard():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>Dashboard index.html not found</h1>")
