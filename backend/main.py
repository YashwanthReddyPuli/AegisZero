import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import numpy as np

# Global variables to store loaded ML artifacts
threat_model = None
vectorizer = None
intrusion_model = None

def load_artifacts():
    global threat_model, vectorizer, intrusion_model
    base_dir = os.path.dirname(__file__)
    
    threat_model_path = os.path.join(base_dir, "models", "threat_model.pkl")
    vectorizer_path = os.path.join(base_dir, "models", "vectorizer.pkl")
    intrusion_model_path = os.path.join(base_dir, "models", "intrusion_model.pkl")

    # Auto-train threat model if missing
    if not os.path.exists(threat_model_path) or not os.path.exists(vectorizer_path):
        from train_threat_model import train_and_save_model
        train_and_save_model()

    # Auto-train intrusion model if missing
    if not os.path.exists(intrusion_model_path):
        from train_intrusion_model import train_and_save_intrusion_model
        train_and_save_intrusion_model()

    threat_model = joblib.load(threat_model_path)
    vectorizer = joblib.load(vectorizer_path)
    intrusion_model = joblib.load(intrusion_model_path)
    
    print("[+] Threat payload model, vectorizer, and NIDS intrusion model successfully loaded into memory.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_artifacts()
    yield

app = FastAPI(
    title="AegisAPI Security Inference Engine",
    description="ML-powered payload scanner & NIDS network traffic intrusion analyzer",
    version="2.0.0",
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

# --- Module 1: Payload Scanner Models ---
class PayloadScanRequest(BaseModel):
    payload: str

class PayloadScanResponse(BaseModel):
    status: str
    payload: str
    threat_detected: bool
    confidence_score: float

# --- Module 2: NIDS Traffic Models ---
class NetworkTraffic(BaseModel):
    connection_duration: float = Field(..., description="Duration of connection in seconds")
    packet_size_bytes: int = Field(..., description="Packet size in bytes")
    failed_login_attempts: int = Field(..., description="Number of failed login attempts")
    protocol_type: int = Field(..., description="0 for TCP, 1 for UDP")

class NetworkTrafficResponse(BaseModel):
    status: str
    intrusion_detected: bool
    confidence_score: float

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "AegisAPI Security Engine",
        "modules": ["Payload Threat Scanner", "Network Intrusion Detection System (NIDS)"]
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
        confidence_score = float(probabilities[prediction])

        return PayloadScanResponse(
            status="success",
            payload=request.payload,
            threat_detected=bool(prediction == 1),
            confidence_score=round(confidence_score, 4)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payload inference error: {str(e)}")

# --- Module 2 Endpoint: NIDS Traffic Analyzer ---
@app.post("/api/v1/analyze-traffic", response_model=NetworkTrafficResponse)
def analyze_traffic(traffic: NetworkTraffic):
    if intrusion_model is None:
        load_artifacts()

    try:
        # Prepare feature vector: [[connection_duration, packet_size_bytes, failed_login_attempts, protocol_type]]
        features = np.array([[
            traffic.connection_duration,
            traffic.packet_size_bytes,
            traffic.failed_login_attempts,
            traffic.protocol_type
        ]])

        prediction = int(intrusion_model.predict(features)[0])
        probabilities = intrusion_model.predict_proba(features)[0]
        confidence_score = float(probabilities[prediction])

        return NetworkTrafficResponse(
            status="success",
            intrusion_detected=bool(prediction == 1),
            confidence_score=round(confidence_score, 4)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Traffic inference error: {str(e)}")
