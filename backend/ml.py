"""
Machine Learning and Data Processing Pipeline for Network Traffic Anomaly Detection.
Implements Isolation Forest, Feature Engineering, Severity Scoring, MLflow Tracking,
and Synthetic Traffic Generation.
"""
import os
import random
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_FILE = os.path.join(MODELS_DIR, "isolation_forest.pkl")
PREPROCESSOR_FILE = os.path.join(MODELS_DIR, "preprocessor.pkl")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Known categories for encoding
PROTOCOLS = ["TCP", "UDP", "ICMP", "OTHER"]
FLAGS = ["SF", "S0", "REJ", "RSTO", "RSTOS0", "SH", "OTH"]
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 3306, 3389, 8080]


class TrafficPreprocessor:
    """Handles feature engineering, scaling, and categorical encoding."""

    def __init__(self):
        self.scaler = RobustScaler()
        self.feature_names: List[str] = []
        self.is_fitted: bool = False

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Derives advanced network traffic metrics from raw flow attributes."""
        df_feat = pd.DataFrame(index=df.index)

        # Basic numericals
        duration = pd.to_numeric(df.get("duration", 0.0), errors="coerce").fillna(0.0)
        packet_count = pd.to_numeric(df.get("packet_count", 1), errors="coerce").fillna(1).clip(lower=1)
        byte_count = pd.to_numeric(df.get("byte_count", 0), errors="coerce").fillna(0).clip(lower=0)
        src_port = pd.to_numeric(df.get("src_port", 0), errors="coerce").fillna(0).astype(int)
        dst_port = pd.to_numeric(df.get("dst_port", 80), errors="coerce").fillna(80).astype(int)
        failed_connections = pd.to_numeric(df.get("failed_connections", 0), errors="coerce").fillna(0)

        df_feat["duration"] = duration
        df_feat["packet_count"] = packet_count
        df_feat["byte_count"] = byte_count
        df_feat["src_port"] = src_port
        df_feat["dst_port"] = dst_port
        df_feat["failed_connections"] = failed_connections

        # Calculated rates
        # Packets per second (avoid division by 0)
        safe_duration = np.where(duration <= 0.0001, 0.001, duration)
        df_feat["packets_per_sec"] = packet_count / safe_duration
        df_feat["bytes_per_sec"] = byte_count / safe_duration
        df_feat["bytes_per_packet"] = byte_count / packet_count

        # Port features
        df_feat["is_privileged_dst_port"] = (dst_port < 1024).astype(int)
        df_feat["is_common_port"] = dst_port.isin(COMMON_PORTS).astype(int)
        df_feat["is_high_src_port"] = (src_port >= 1024).astype(int)

        # Categorical Encoding: Protocol
        raw_proto = df.get("protocol", "TCP").astype(str).str.upper()
        for proto in PROTOCOLS:
            df_feat[f"proto_{proto}"] = (raw_proto == proto).astype(int)

        # Categorical Encoding: TCP Flag
        raw_flag = df.get("flag", "SF").astype(str).str.upper()
        for flag in FLAGS:
            df_feat[f"flag_{flag}"] = (raw_flag == flag).astype(int)

        return df_feat

    def fit(self, df: pd.DataFrame) -> "TrafficPreprocessor":
        """Fits the preprocessor on raw training data."""
        df_feat = self.engineer_features(df)
        self.feature_names = list(df_feat.columns)
        self.scaler.fit(df_feat.values)
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transforms raw input data into scaled feature matrix."""
        if not self.is_fitted:
            # Fallback auto-fit on available data if not fitted yet
            self.fit(df)

        df_feat = self.engineer_features(df)
        # Ensure all columns match fit schema
        for col in self.feature_names:
            if col not in df_feat.columns:
                df_feat[col] = 0
        df_feat = df_feat[self.feature_names]

        # Handle any NaN/Inf
        X = df_feat.values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        return self.scaler.transform(X)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)


class AnomalyDetector:
    """Wrapper around Isolation Forest with continuous anomaly scoring and severity ranking."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.preprocessor = TrafficPreprocessor()
        self.min_score: float = -0.5
        self.max_score: float = 0.5
        self.is_trained: bool = False

    def train(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Trains Isolation Forest model on network traffic data."""
        X_scaled = self.preprocessor.fit_transform(df)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Calculate decision function scores on training data for calibration
        raw_scores = self.model.decision_function(X_scaled)
        self.min_score = float(np.percentile(raw_scores, 1))
        self.max_score = float(np.percentile(raw_scores, 99))
        if self.min_score >= self.max_score:
            self.min_score -= 0.1
            self.max_score += 0.1

        # Predict anomalies on training data
        preds = self.model.predict(X_scaled)
        num_anomalies = int(np.sum(preds == -1))
        anomaly_ratio = float(num_anomalies / len(df))

        # Save artifacts
        self.save()

        return {
            "num_samples": len(df),
            "num_anomalies": num_anomalies,
            "anomaly_rate_pct": round(anomaly_ratio * 100.0, 2),
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "features_count": len(self.preprocessor.feature_names),
        }

    def compute_anomaly_scores(self, raw_decision_scores: np.ndarray) -> np.ndarray:
        """
        Converts Isolation Forest decision function scores to a 0 - 100 intuitive anomaly scale.
        In Isolation Forest, lower raw score = more abnormal.
        Normalized: 0 = completely normal, 100 = extreme anomaly.
        """
        # Invert so higher = more abnormal
        span = max(self.max_score - self.min_score, 1e-5)
        # Raw scores typically range from -0.3 to +0.3
        # If score <= min_score -> 100, if score >= max_score -> 0
        normalized = (self.max_score - raw_decision_scores) / span
        # Map with sigmoid-like curve or scaling to [0, 100]
        scaled = np.clip(normalized * 100.0, 0.0, 100.0)
        return scaled

    def classify_severity(self, anomaly_score: float) -> str:
        """Classifies continuous anomaly score into 5 severity tiers."""
        if anomaly_score >= 85.0:
            return "Critical"
        elif anomaly_score >= 70.0:
            return "High"
        elif anomaly_score >= 55.0:
            return "Medium"
        elif anomaly_score >= 40.0:
            return "Low"
        return "Normal"

    def diagnose_anomaly_type(self, row: Dict[str, Any], is_anomaly: bool) -> str:
        """Provides heuristic cybersecurity behavior diagnostic for anomalous traffic."""
        if not is_anomaly:
            return "Benign"

        packet_count = float(row.get("packet_count", 0))
        byte_count = float(row.get("byte_count", 0))
        duration = float(row.get("duration", 0))
        failed_conns = float(row.get("failed_connections", 0))
        flag = str(row.get("flag", "SF")).upper()
        dst_port = int(row.get("dst_port", 80))
        protocol = str(row.get("protocol", "TCP")).upper()

        packets_per_sec = packet_count / max(duration, 0.01)

        if failed_conns >= 3 or (dst_port in [22, 21, 3389] and failed_conns >= 1):
            return "Brute-Force Behavior"
        elif packets_per_sec > 500 or packet_count > 1000:
            return "DDoS / Traffic Spike"
        elif flag in ["S0", "REJ", "RSTOS0"] or (packet_count <= 3 and byte_count < 200 and duration < 0.1):
            return "Port Scanning"
        elif byte_count > 500000 or (duration > 30 and byte_count > 100000):
            return "Data Exfiltration"
        elif protocol == "ICMP" and packet_count > 50:
            return "ICMP Flood"
        elif flag in ["SH", "OTH"]:
            return "Abnormal Connection Flags"
        else:
            return "Unusual Traffic Pattern"

    def predict(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Generates predictions, anomaly scores, and severity classifications for input records."""
        if self.model is None or not self.preprocessor.is_fitted:
            self.load()

        X_scaled = self.preprocessor.transform(df)
        preds = self.model.predict(X_scaled)  # 1 for inlier, -1 for outlier
        raw_scores = self.model.decision_function(X_scaled)
        anomaly_scores = self.compute_anomaly_scores(raw_scores)

        results = []
        records_dict = df.to_dict(orient="records")

        for i, row in enumerate(records_dict):
            score = float(anomaly_scores[i])
            is_anom = bool(preds[i] == -1 or score >= 50.0)
            sev = self.classify_severity(score)
            anom_type = self.diagnose_anomaly_type(row, is_anom)

            result_item = {
                **row,
                "is_anomaly": is_anom,
                "anomaly_score": round(score, 2),
                "severity": sev,
                "anomaly_type": anom_type,
            }
            results.append(result_item)

        return results

    def save(self):
        """Serializes model and preprocessor to disk."""
        joblib.dump(self.model, MODEL_FILE)
        joblib.dump(
            {
                "preprocessor": self.preprocessor,
                "min_score": self.min_score,
                "max_score": self.max_score,
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
            },
            PREPROCESSOR_FILE,
        )

    def load(self):
        """Loads serialized model and preprocessor from disk."""
        if os.path.exists(MODEL_FILE) and os.path.exists(PREPROCESSOR_FILE):
            self.model = joblib.load(MODEL_FILE)
            meta = joblib.load(PREPROCESSOR_FILE)
            self.preprocessor = meta["preprocessor"]
            self.min_score = meta.get("min_score", -0.5)
            self.max_score = meta.get("max_score", 0.5)
            self.n_estimators = meta.get("n_estimators", 100)
            self.contamination = meta.get("contamination", 0.05)
            self.is_trained = True
        else:
            # Fallback: create & train on synthetic baseline if no model exists
            self.train_baseline()

    def train_baseline(self):
        """Generates baseline data and trains initial model."""
        generator = SyntheticTrafficGenerator()
        df = generator.generate_dataset(num_samples=2500, anomaly_ratio=0.06)
        csv_path = os.path.join(DATA_DIR, "network_traffic.csv")
        df.to_csv(csv_path, index=False)
        self.train(df)


class MLflowTracker:
    """Handles MLflow experiment tracking for training runs."""

    EXPERIMENT_NAME = "Network_Traffic_Anomaly_Detection"

    @classmethod
    def log_training_run(
        cls,
        detector: AnomalyDetector,
        training_stats: Dict[str, Any],
        df_train: pd.DataFrame,
    ) -> Optional[str]:
        """Logs training run, hyperparameters, metrics, and model artifact to MLflow."""
        try:
            # Configure MLflow local tracking
            mlflow_dir = os.path.join(BASE_DIR, "mlruns")
            mlflow.set_tracking_uri(f"file:///{mlflow_dir.replace('\\', '/')}")
            mlflow.set_experiment(cls.EXPERIMENT_NAME)

            with mlflow.start_run() as run:
                run_id = run.info.run_id

                # Log parameters
                mlflow.log_params({
                    "model_type": "IsolationForest",
                    "n_estimators": detector.n_estimators,
                    "contamination": detector.contamination,
                    "random_state": detector.random_state,
                    "feature_count": training_stats.get("features_count", 0),
                })

                # Log metrics
                mlflow.log_metrics({
                    "num_samples": training_stats.get("num_samples", 0),
                    "num_anomalies_detected": training_stats.get("num_anomalies", 0),
                    "anomaly_rate_pct": training_stats.get("anomaly_rate_pct", 0.0),
                })

                # Log model artifact
                if detector.model is not None:
                    mlflow.sklearn.log_model(detector.model, artifact_path="isolation_forest_model")

                return run_id
        except Exception as e:
            print(f"[MLflow] Warning: Failed to log run to MLflow: {e}")
            return None


class SyntheticTrafficGenerator:
    """Generates realistic synthetic enterprise network traffic with realistic attack patterns."""

    BENIGN_SERVICES = [
        {"proto": "TCP", "dst_port": 443, "flag": "SF", "duration": (0.05, 5.0), "packets": (4, 120), "bytes": (400, 45000)},
        {"proto": "TCP", "dst_port": 80, "flag": "SF", "duration": (0.02, 2.5), "packets": (3, 60), "bytes": (200, 15000)},
        {"proto": "UDP", "dst_port": 53, "flag": "SF", "duration": (0.005, 0.05), "packets": (1, 4), "bytes": (60, 400)},
        {"proto": "UDP", "dst_port": 123, "flag": "SF", "duration": (0.001, 0.01), "packets": (1, 2), "bytes": (48, 96)},
        {"proto": "TCP", "dst_port": 22, "flag": "SF", "duration": (1.0, 60.0), "packets": (20, 300), "bytes": (1500, 80000)},
        {"proto": "TCP", "dst_port": 3306, "flag": "SF", "duration": (0.01, 0.8), "packets": (2, 25), "bytes": (150, 8000)},
    ]

    INTERNAL_SUBNETS = ["192.168.1.", "10.0.0.", "172.16.10."]
    EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "151.101.1.69", "185.199.108.153", "52.84.12.33"]
    ATTACKER_IPS = ["198.51.100.44", "203.0.113.88", "192.0.2.105", "45.154.255.7", "185.220.101.5"]

    @classmethod
    def random_internal_ip(cls) -> str:
        return random.choice(cls.INTERNAL_SUBNETS) + str(random.randint(2, 250))

    @classmethod
    def generate_single_flow(cls, force_anomaly_type: Optional[str] = None) -> Dict[str, Any]:
        """Generates a single synthetic network flow record."""
        now = datetime.utcnow()

        if force_anomaly_type:
            attack_type = force_anomaly_type
        else:
            is_attack = random.random() < 0.08
            attack_type = random.choice([
                "ddos", "port_scan", "brute_force", "exfiltration", "icmp_flood"
            ]) if is_attack else "benign"

        if attack_type == "ddos":
            # High packet rate spike
            src_ip = random.choice(cls.ATTACKER_IPS)
            dst_ip = "192.168.1.10"
            duration = round(random.uniform(0.01, 0.5), 4)
            packet_count = random.randint(3000, 15000)
            byte_count = packet_count * random.randint(40, 120)
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 8080]),
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration": duration,
                "flag": random.choice(["S0", "RSTO", "SF"]),
                "failed_connections": random.randint(0, 5),
            }

        elif attack_type == "port_scan":
            # Fast scan probe, small packets, S0/REJ flags
            src_ip = random.choice(cls.ATTACKER_IPS)
            dst_ip = cls.random_internal_ip()
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "src_port": random.randint(40000, 65535),
                "dst_port": random.randint(1, 1024),
                "packet_count": random.randint(1, 3),
                "byte_count": random.randint(40, 180),
                "duration": round(random.uniform(0.001, 0.02), 4),
                "flag": random.choice(["S0", "REJ"]),
                "failed_connections": 1,
            }

        elif attack_type == "brute_force":
            # Multiple failed connection attempts on SSH / RDP / FTP
            src_ip = random.choice(cls.ATTACKER_IPS)
            dst_ip = "192.168.1.50"
            target_port = random.choice([22, 21, 3389])
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "src_port": random.randint(20000, 60000),
                "dst_port": target_port,
                "packet_count": random.randint(15, 60),
                "byte_count": random.randint(1200, 5000),
                "duration": round(random.uniform(2.0, 15.0), 4),
                "flag": random.choice(["REJ", "RSTO", "SF"]),
                "failed_connections": random.randint(5, 25),
            }

        elif attack_type == "exfiltration":
            # Massive outbound bytes transfer
            src_ip = "192.168.1.100"
            dst_ip = random.choice(cls.ATTACKER_IPS)
            duration = round(random.uniform(45.0, 300.0), 4)
            packet_count = random.randint(1500, 8000)
            byte_count = random.randint(1500000, 25000000)  # 1.5MB - 25MB
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([443, 8443, 2222]),
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration": duration,
                "flag": "SF",
                "failed_connections": 0,
            }

        elif attack_type == "icmp_flood":
            src_ip = random.choice(cls.ATTACKER_IPS)
            dst_ip = "192.168.1.1"
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "ICMP",
                "src_port": 0,
                "dst_port": 0,
                "packet_count": random.randint(800, 5000),
                "byte_count": random.randint(50000, 300000),
                "duration": round(random.uniform(0.1, 1.0), 4),
                "flag": "SF",
                "failed_connections": 0,
            }

        else:
            # Benign enterprise traffic
            svc = random.choice(cls.BENIGN_SERVICES)
            src_ip = cls.random_internal_ip()
            dst_ip = random.choice(cls.EXTERNAL_IPS) if random.random() < 0.7 else cls.random_internal_ip()
            duration = round(random.uniform(*svc["duration"]), 4)
            packet_count = random.randint(*svc["packets"])
            byte_count = random.randint(*svc["bytes"])
            return {
                "timestamp": now.isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": svc["proto"],
                "src_port": random.randint(1024, 65535),
                "dst_port": svc["dst_port"],
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration": duration,
                "flag": svc["flag"],
                "failed_connections": 0 if random.random() > 0.03 else 1,
            }

    def generate_dataset(self, num_samples: int = 3000, anomaly_ratio: float = 0.07) -> pd.DataFrame:
        """Generates a dataset of realistic network traffic records spanning over past 24 hours."""
        records = []
        base_time = datetime.utcnow() - timedelta(hours=24)
        time_step_sec = (24 * 3600) / max(num_samples, 1)

        for i in range(num_samples):
            flow_time = base_time + timedelta(seconds=i * time_step_sec + random.uniform(0, 5))
            is_anomaly = random.random() < anomaly_ratio
            if is_anomaly:
                attack_type = random.choice(["ddos", "port_scan", "brute_force", "exfiltration", "icmp_flood"])
                flow = self.generate_single_flow(force_anomaly_type=attack_type)
            else:
                flow = self.generate_single_flow(force_anomaly_type="benign")

            flow["timestamp"] = flow_time.isoformat()
            records.append(flow)

        return pd.DataFrame(records)


# Global singleton detector instance
detector_instance = AnomalyDetector()
