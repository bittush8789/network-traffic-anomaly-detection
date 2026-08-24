"""
Database Layer for Network Traffic Anomaly Detection.
Uses SQLite and SQLAlchemy for persistence.
"""
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    DateTime,
    Boolean,
    Text,
    desc,
    func,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Base directory for DB storage
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "network_traffic.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class TrafficRecord(Base):
    """Stores analyzed network traffic flow records."""
    __tablename__ = "traffic_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    protocol = Column(String(10), index=True, nullable=False)  # TCP, UDP, ICMP
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, index=True, nullable=False)
    packet_count = Column(Integer, default=1)
    byte_count = Column(Integer, default=0)
    duration = Column(Float, default=0.0)  # in seconds
    flag = Column(String(10), default="SF")  # SF, S0, REJ, RSTO, etc.
    failed_connections = Column(Integer, default=0)
    
    # Anomaly fields
    is_anomaly = Column(Boolean, default=False, index=True)
    anomaly_score = Column(Float, default=0.0)  # 0.0 - 100.0 (higher = more abnormal)
    severity = Column(String(20), default="Normal", index=True)  # Normal, Low, Medium, High, Critical
    anomaly_type = Column(String(50), default="Benign")  # e.g., DDoS Spike, Port Scan, Brute Force, Exfiltration, Benign
    
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "flag": self.flag,
            "failed_connections": self.failed_connections,
            "is_anomaly": bool(self.is_anomaly),
            "anomaly_score": round(self.anomaly_score, 2),
            "severity": self.severity,
            "anomaly_type": self.anomaly_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ModelTrainingRun(Base):
    """Tracks training metadata and MLflow experiment runs in SQLite."""
    __tablename__ = "model_training_runs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    model_name = Column(String(100), default="IsolationForest")
    n_estimators = Column(Integer, default=100)
    contamination = Column(Float, default=0.05)
    max_samples = Column(String(50), default="auto")
    num_samples = Column(Integer, default=0)
    num_anomalies_detected = Column(Integer, default=0)
    anomaly_rate_pct = Column(Float, default=0.0)
    mlflow_run_id = Column(String(100), nullable=True)
    status = Column(String(20), default="SUCCESS")
    notes = Column(Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "model_name": self.model_name,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "max_samples": self.max_samples,
            "num_samples": self.num_samples,
            "num_anomalies_detected": self.num_anomalies_detected,
            "anomaly_rate_pct": round(self.anomaly_rate_pct, 2),
            "mlflow_run_id": self.mlflow_run_id,
            "status": self.status,
            "notes": self.notes,
        }


def init_db():
    """Initializes SQLite database tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_traffic_records(records: List[Dict[str, Any]], db: Optional[Session] = None) -> int:
    """Inserts a batch of analyzed traffic records into SQLite."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        db_objs = []
        for r in records:
            ts = r.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.utcnow()
            elif not isinstance(ts, datetime):
                ts = datetime.utcnow()

            obj = TrafficRecord(
                timestamp=ts,
                src_ip=str(r.get("src_ip", "0.0.0.0")),
                dst_ip=str(r.get("dst_ip", "0.0.0.0")),
                protocol=str(r.get("protocol", "TCP")).upper(),
                src_port=int(r.get("src_port", 0)),
                dst_port=int(r.get("dst_port", 80)),
                packet_count=int(r.get("packet_count", 1)),
                byte_count=int(r.get("byte_count", 0)),
                duration=float(r.get("duration", 0.0)),
                flag=str(r.get("flag", "SF")),
                failed_connections=int(r.get("failed_connections", 0)),
                is_anomaly=bool(r.get("is_anomaly", False)),
                anomaly_score=float(r.get("anomaly_score", 0.0)),
                severity=str(r.get("severity", "Normal")),
                anomaly_type=str(r.get("anomaly_type", "Benign")),
            )
            db_objs.append(obj)

        db.bulk_save_objects(db_objs)
        db.commit()
        return len(db_objs)
    finally:
        if close_db:
            db.close()


def get_traffic_records(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    anomaly_only: bool = False,
    search_ip: Optional[str] = None,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """Retrieves paginated and filtered traffic records."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        query = db.query(TrafficRecord)

        if anomaly_only:
            query = query.filter(TrafficRecord.is_anomaly == True)
        if severity and severity.lower() != "all":
            query = query.filter(TrafficRecord.severity.ilike(severity))
        if protocol and protocol.lower() != "all":
            query = query.filter(TrafficRecord.protocol.ilike(protocol))
        if search_ip:
            s = f"%{search_ip.strip()}%"
            query = query.filter((TrafficRecord.src_ip.like(s)) | (TrafficRecord.dst_ip.like(s)))

        total_count = query.count()
        records = query.order_by(desc(TrafficRecord.timestamp)).offset(offset).limit(limit).all()

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "items": [r.to_dict() for r in records],
        }
    finally:
        if close_db:
            db.close()


def get_traffic_stats(db: Optional[Session] = None) -> Dict[str, Any]:
    """Computes aggregate analytics KPIs for the dashboard."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        total_records = db.query(func.count(TrafficRecord.id)).scalar() or 0
        total_anomalies = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.is_anomaly == True).scalar() or 0
        critical_count = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.severity == "Critical").scalar() or 0
        high_count = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.severity == "High").scalar() or 0
        medium_count = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.severity == "Medium").scalar() or 0
        low_count = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.severity == "Low").scalar() or 0
        normal_count = db.query(func.count(TrafficRecord.id)).filter(TrafficRecord.severity == "Normal").scalar() or 0

        anomaly_rate = (total_anomalies / total_records * 100.0) if total_records > 0 else 0.0

        # Protocol breakdown
        protocol_counts = (
            db.query(TrafficRecord.protocol, func.count(TrafficRecord.id))
            .group_by(TrafficRecord.protocol)
            .all()
        )
        protocols = {p or "UNKNOWN": count for p, count in protocol_counts}

        # Top suspicious source IPs
        top_suspicious_ips = (
            db.query(
                TrafficRecord.src_ip,
                func.count(TrafficRecord.id).label("anomaly_count"),
                func.avg(TrafficRecord.anomaly_score).label("avg_score")
            )
            .filter(TrafficRecord.is_anomaly == True)
            .group_by(TrafficRecord.src_ip)
            .order_by(desc("anomaly_count"))
            .limit(5)
            .all()
        )

        top_ips = [
            {"ip": ip, "count": count, "avg_score": round(float(avg_s or 0.0), 2)}
            for ip, count, avg_s in top_suspicious_ips
        ]

        # Anomaly Type Breakdown
        anomaly_type_counts = (
            db.query(TrafficRecord.anomaly_type, func.count(TrafficRecord.id))
            .filter(TrafficRecord.is_anomaly == True)
            .group_by(TrafficRecord.anomaly_type)
            .all()
        )
        anomaly_types = {t or "Unknown": count for t, count in anomaly_type_counts}

        return {
            "total_records": total_records,
            "total_anomalies": total_anomalies,
            "anomaly_rate_pct": round(anomaly_rate, 2),
            "severity_counts": {
                "Critical": critical_count,
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count,
                "Normal": normal_count,
            },
            "protocol_counts": protocols,
            "top_suspicious_ips": top_ips,
            "anomaly_types": anomaly_types,
        }
    finally:
        if close_db:
            db.close()


def get_timeline_data(points: int = 24, db: Optional[Session] = None) -> List[Dict[str, Any]]:
    """Retrieves time-series data for charting volume and anomaly trends."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        # Get recent records ordered by timestamp asc
        records = (
            db.query(TrafficRecord.timestamp, TrafficRecord.is_anomaly, TrafficRecord.anomaly_score)
            .order_by(TrafficRecord.timestamp.asc())
            .all()
        )

        if not records:
            return []

        # Group records into time buckets
        total_len = len(records)
        bucket_size = max(1, total_len // points)
        timeline = []

        for i in range(0, total_len, bucket_size):
            chunk = records[i : i + bucket_size]
            if not chunk:
                continue
            ts = chunk[-1].timestamp.strftime("%H:%M:%S") if chunk[-1].timestamp else f"T{i}"
            vol = len(chunk)
            anom = sum(1 for c in chunk if c.is_anomaly)
            avg_score = sum(c.anomaly_score for c in chunk) / vol if vol > 0 else 0

            timeline.append({
                "time": ts,
                "traffic_volume": vol,
                "anomalies": anom,
                "avg_anomaly_score": round(avg_score, 2),
            })

        return timeline[-points:]
    finally:
        if close_db:
            db.close()


def save_training_run(run_data: Dict[str, Any], db: Optional[Session] = None) -> ModelTrainingRun:
    """Saves a model training run record."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        run = ModelTrainingRun(
            model_name=run_data.get("model_name", "IsolationForest"),
            n_estimators=run_data.get("n_estimators", 100),
            contamination=run_data.get("contamination", 0.05),
            max_samples=str(run_data.get("max_samples", "auto")),
            num_samples=run_data.get("num_samples", 0),
            num_anomalies_detected=run_data.get("num_anomalies_detected", 0),
            anomaly_rate_pct=run_data.get("anomaly_rate_pct", 0.0),
            mlflow_run_id=run_data.get("mlflow_run_id"),
            status=run_data.get("status", "SUCCESS"),
            notes=run_data.get("notes"),
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run
    finally:
        if close_db:
            db.close()


def get_training_runs(limit: int = 10, db: Optional[Session] = None) -> List[Dict[str, Any]]:
    """Retrieves past model training runs."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        runs = db.query(ModelTrainingRun).order_by(desc(ModelTrainingRun.timestamp)).limit(limit).all()
        return [r.to_dict() for r in runs]
    finally:
        if close_db:
            db.close()


def clear_database(db: Optional[Session] = None):
    """Deletes all traffic records and model runs for a fresh reset."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        db.query(TrafficRecord).delete()
        db.commit()
    finally:
        if close_db:
            db.close()
