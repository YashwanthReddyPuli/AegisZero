import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import numpy as np
import pandas as pd

# Global variables to store loaded ML artifacts
threat_model = None
vectorizer = None
intrusion_model = None
auth_model = None
behavior_model = None

def load_artifacts():
    global threat_model, vectorizer, intrusion_model, auth_model, behavior_model
    base_dir = os.path.dirname(__file__)
    
    threat_model_path = os.path.join(base_dir, "models", "threat_model.pkl")
    vectorizer_path = os.path.join(base_dir, "models", "vectorizer.pkl")
    intrusion_model_path = os.path.join(base_dir, "models", "intrusion_model.pkl")
    auth_model_path = os.path.join(base_dir, "models", "auth_model.pkl")
    behavior_model_path = os.path.join(base_dir, "models", "behavior_model.pkl")

    if not os.path.exists(threat_model_path) or not os.path.exists(vectorizer_path):
        from train_threat_model import train_and_save_model
        train_and_save_model()

    if not os.path.exists(intrusion_model_path):
        from train_intrusion_model import train_and_save_intrusion_model
        train_and_save_intrusion_model()

    if not os.path.exists(auth_model_path):
        from train_auth_model import train_and_save_auth_model
        train_and_save_auth_model()

    if not os.path.exists(behavior_model_path):
        from train_behavior_model import train_and_save_behavior_model
        train_and_save_behavior_model()

    threat_model = joblib.load(threat_model_path)
    vectorizer = joblib.load(vectorizer_path)
    intrusion_model = joblib.load(intrusion_model_path)
    auth_model = joblib.load(auth_model_path)
    behavior_model = joblib.load(behavior_model_path)
    
    print("[+] All 4 AegisAPI ML models (Payload, NIDS, Auth, and OneClassSVM Behavior) loaded into memory.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_artifacts()
    yield

app = FastAPI(
    title="AegisAPI Security Inference Engine",
    description="Full-suite ML Security Module (Payload Scanner, NIDS, Risk-Based Auth, System Behavior Anomaly Engine)",
    version="4.0.0",
    lifespan=lifespan
)

# Enable CORS for Next.js SOC Dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Module 1 Models ---
class PayloadScanRequest(BaseModel):
    payload: str

class PayloadScanResponse(BaseModel):
    status: str
    payload: str
    threat_detected: bool
    confidence_score: float

# --- Module 2 Models ---
class NetworkTraffic(BaseModel):
    connection_duration: float
    packet_size_bytes: int
    failed_login_attempts: int
    protocol_type: int

class NetworkTrafficResponse(BaseModel):
    status: str
    intrusion_detected: bool
    confidence_score: float

# --- Module 3 Models ---
class LoginAttempt(BaseModel):
    hour_of_day: int = Field(..., ge=0, le=23)
    failed_attempts_24h: int = Field(..., ge=0)
    distance_from_home_km: float = Field(..., ge=0.0)

class LoginAttemptResponse(BaseModel):
    status: str
    reason: str
    anomaly_score: float

# --- Module 4 Models: System Behavior Anomaly Engine ---
class BehaviorMetrics(BaseModel):
    requests_per_minute: float = Field(..., ge=0.0)
    data_transfer_mb: float = Field(..., ge=0.0)
    error_rate_percentage: float = Field(..., ge=0.0, le=100.0)

class BehaviorMetricsResponse(BaseModel):
    status: str
    action: str
    anomaly_score: float

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "AegisAPI Security Engine",
        "modules": [
            "Payload Threat Scanner",
            "Network Intrusion Detection System (NIDS)",
            "Risk-Based Authentication Gateway",
            "System Behavior Anomaly Engine"
        ]
    }

# --- Module 1 Endpoint ---
@app.post("/api/v1/scan-payload", response_model=PayloadScanResponse)
def scan_payload(request: PayloadScanRequest):
    if threat_model is None or vectorizer is None:
        load_artifacts()

    try:
        features = vectorizer.transform([request.payload])
        prediction = int(threat_model.predict(features)[0])
        probabilities = threat_model.predict_proba(features)[0]

        return PayloadScanResponse(
            status="success",
            payload=request.payload,
            threat_detected=bool(prediction == 1),
            confidence_score=round(float(probabilities[prediction]), 4)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payload inference error: {str(e)}")

# --- Module 2 Endpoint ---
@app.post("/api/v1/analyze-traffic", response_model=NetworkTrafficResponse)
def analyze_traffic(traffic: NetworkTraffic):
    if intrusion_model is None:
        load_artifacts()

    try:
        features = pd.DataFrame([{
            'connection_duration': traffic.connection_duration,
            'packet_size_bytes': traffic.packet_size_bytes,
            'failed_login_attempts': traffic.failed_login_attempts,
            'protocol_type': traffic.protocol_type
        }])

        prediction = int(intrusion_model.predict(features)[0])
        probabilities = intrusion_model.predict_proba(features)[0]

        return NetworkTrafficResponse(
            status="success",
            intrusion_detected=bool(prediction == 1),
            confidence_score=round(float(probabilities[prediction]), 4)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Traffic inference error: {str(e)}")

# --- Module 3 Endpoint ---
@app.post("/api/v1/verify-login", response_model=LoginAttemptResponse)
def verify_login(attempt: LoginAttempt):
    if auth_model is None:
        load_artifacts()

    try:
        features = pd.DataFrame([{
            'hour_of_day': attempt.hour_of_day,
            'failed_attempts_24h': attempt.failed_attempts_24h,
            'distance_from_home_km': attempt.distance_from_home_km
        }])

        prediction = int(auth_model.predict(features)[0])
        raw_score = float(auth_model.score_samples(features)[0])
        anomaly_score = round(abs(raw_score), 4)

        if prediction == -1:
            return LoginAttemptResponse(
                status="blocked",
                reason="High-Risk Anomaly Detected (MFA Triggered)",
                anomaly_score=anomaly_score
            )
        else:
            return LoginAttemptResponse(
                status="allowed",
                reason="Authentication Approved",
                anomaly_score=anomaly_score
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auth inference error: {str(e)}")

# --- Module 4 Endpoint: System Behavior Anomaly Engine ---
@app.post("/api/v1/analyze-behavior", response_model=BehaviorMetricsResponse)
def analyze_behavior(metrics: BehaviorMetrics):
    if behavior_model is None:
        load_artifacts()

    try:
        features = pd.DataFrame([{
            'requests_per_minute': metrics.requests_per_minute,
            'data_transfer_mb': metrics.data_transfer_mb,
            'error_rate_percentage': metrics.error_rate_percentage
        }])

        # OneClassSVM prediction: -1 = Anomaly Outlier, 1 = Normal Baseline
        prediction = int(behavior_model.predict(features)[0])
        raw_score = float(behavior_model.score_samples(features)[0])
        anomaly_score = round(abs(raw_score), 4)

        if prediction == -1:
            return BehaviorMetricsResponse(
                status="anomaly_detected",
                action="Rate Limit Applied",
                anomaly_score=anomaly_score
            )
        else:
            return BehaviorMetricsResponse(
                status="normal",
                action="Nominal",
                anomaly_score=anomaly_score
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Behavior inference error: {str(e)}")
