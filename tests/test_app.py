"""
Automated Test Suite for Network Traffic Anomaly Detection.
Tests ML pipeline, SQLite persistence, FastAPI endpoints, Prometheus metrics, and MLflow logging.
"""
import io
import pytest
import pandas as pd
from fastapi.testclient import TestClient
from backend.main import app
from backend.ml import TrafficPreprocessor, AnomalyDetector, SyntheticTrafficGenerator
from backend.database import (
    init_db,
    save_traffic_records,
    get_traffic_records,
    get_traffic_stats,
    clear_database,
)

client = TestClient(app)


def setup_module():
    """Setup database before tests run."""
    init_db()


def test_synthetic_traffic_generator():
    """Verify synthetic traffic generator produces valid flows with expected schema."""
    gen = SyntheticTrafficGenerator()
    df = gen.generate_dataset(num_samples=50, anomaly_ratio=0.1)
    
    assert len(df) == 50
    expected_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_count", "byte_count", "duration", "flag", "failed_connections"]
    for col in expected_cols:
        assert col in df.columns


def test_feature_preprocessor():
    """Verify preprocessor handles numeric feature derivation and categorical encoding."""
    gen = SyntheticTrafficGenerator()
    df = gen.generate_dataset(num_samples=20)
    
    preprocessor = TrafficPreprocessor()
    X = preprocessor.fit_transform(df)
    
    assert X.shape[0] == 20
    assert X.shape[1] > 10  # derived features + categorical one-hot columns
    assert not pd.isna(X).any()


def test_anomaly_detector_train_and_predict():
    """Verify Isolation Forest training, scoring, and severity classification."""
    gen = SyntheticTrafficGenerator()
    df_train = gen.generate_dataset(num_samples=100, anomaly_ratio=0.1)
    
    detector = AnomalyDetector(n_estimators=30, contamination=0.1)
    stats = detector.train(df_train)
    
    assert stats["num_samples"] == 100
    assert stats["num_anomalies"] > 0
    assert detector.is_trained

    # Test prediction on a normal flow vs an extreme DDoS flow
    test_flows = pd.DataFrame([
        {
            "src_ip": "192.168.1.15",
            "dst_ip": "104.244.42.1",
            "protocol": "TCP",
            "src_port": 50123,
            "dst_port": 443,
            "packet_count": 10,
            "byte_count": 3500,
            "duration": 0.2,
            "flag": "SF",
            "failed_connections": 0,
        },
        {
            "src_ip": "198.51.100.44",
            "dst_ip": "192.168.1.10",
            "protocol": "TCP",
            "src_port": 58921,
            "dst_port": 80,
            "packet_count": 15000,
            "byte_count": 1200000,
            "duration": 0.05,
            "flag": "S0",
            "failed_connections": 0,
        },
    ])
    
    results = detector.predict(test_flows)
    assert len(results) == 2
    assert "anomaly_score" in results[0]
    assert "severity" in results[0]
    assert "anomaly_type" in results[0]
    # The second flow is a heavy DDoS attack and should have a higher score
    assert results[1]["anomaly_score"] >= results[0]["anomaly_score"]


def test_fastapi_health_endpoint():
    """Verify health endpoint."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True


def test_fastapi_predict_single_endpoint():
    """Verify single flow prediction endpoint."""
    payload = {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "protocol": "UDP",
        "src_port": 53210,
        "dst_port": 53,
        "packet_count": 2,
        "byte_count": 140,
        "duration": 0.01,
        "flag": "SF",
        "failed_connections": 0,
    }
    response = client.post("/api/predict/single", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "anomaly_score" in data
    assert "severity" in data
    assert "latency_ms" in data


def test_fastapi_predict_batch_csv():
    """Verify batch CSV file upload and processing."""
    gen = SyntheticTrafficGenerator()
    df = gen.generate_dataset(num_samples=15)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    
    response = client.post(
        "/api/predict/batch",
        files={"file": ("test_traffic.csv", io.BytesIO(csv_bytes), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_records_processed"] == 15
    assert data["saved_to_database"] == 15


def test_fastapi_stats_and_timeline():
    """Verify analytics and time-series endpoints."""
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_records" in stats
    assert "severity_counts" in stats
    assert stats["total_records"] > 0

    timeline_res = client.get("/api/timeline?points=10")
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()
    assert isinstance(timeline, list)


def test_fastapi_simulate_traffic():
    """Verify live traffic simulator endpoint."""
    response = client.post("/api/simulate/traffic", json={"count": 3})
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 3
    assert len(data["flows"]) == 3


def test_prometheus_metrics_endpoint():
    """Verify Prometheus /metrics returns scrapable metrics."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "network_traffic_flows_total" in response.text
    assert "network_model_contamination" in response.text


def test_fastapi_train_endpoint():
    """Verify model retraining endpoint with MLflow logging."""
    payload = {
        "n_estimators": 50,
        "contamination": 0.08,
        "use_existing_db": False,
    }
    response = client.post("/api/train", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "mlflow_run_id" in data
    assert data["training_stats"]["n_estimators"] == 50
