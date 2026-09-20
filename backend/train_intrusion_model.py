import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

def train_and_save_intrusion_model():
    np.random.seed(42)

    # 1. Generate Synthetic Network Traffic Dataset
    # Features: connection_duration, packet_size_bytes, failed_login_attempts, protocol_type (0=TCP, 1=UDP)

    # --- Normal Traffic (Label 0) ---
    normal_count = 300
    normal_data = {
        'connection_duration': np.random.uniform(0.1, 10.0, normal_count),
        'packet_size_bytes': np.random.randint(64, 1500, normal_count),
        'failed_login_attempts': np.random.choice([0, 0, 0, 0, 1], normal_count),
        'protocol_type': np.random.choice([0, 1], normal_count, p=[0.7, 0.3]),
        'label': [0] * normal_count
    }

    # --- DDoS Flood Intrusion (Label 1) ---
    ddos_count = 150
    ddos_data = {
        'connection_duration': np.random.uniform(0.001, 0.05, ddos_count),
        'packet_size_bytes': np.random.randint(20000, 65535, ddos_count),
        'failed_login_attempts': [0] * ddos_count,
        'protocol_type': np.random.choice([0, 1], ddos_count, p=[0.2, 0.8]),
        'label': [1] * ddos_count
    }

    # --- SSH / Brute Force Intrusion (Label 1) ---
    brute_count = 150
    brute_data = {
        'connection_duration': np.random.uniform(5.0, 120.0, brute_count),
        'packet_size_bytes': np.random.randint(128, 512, brute_count),
        'failed_login_attempts': np.random.randint(3, 20, brute_count),
        'protocol_type': [0] * brute_count,  # TCP
        'label': [1] * brute_count
    }

    # --- Port Scan Intrusion (Label 1) ---
    scan_count = 150
    scan_data = {
        'connection_duration': np.random.uniform(0.0001, 0.005, scan_count),
        'packet_size_bytes': np.random.randint(20, 64, scan_count),
        'failed_login_attempts': [0] * scan_count,
        'protocol_type': [0] * scan_count,  # TCP
        'label': [1] * scan_count
    }

    # Combine into single DataFrame
    df_normal = pd.DataFrame(normal_data)
    df_ddos = pd.DataFrame(ddos_data)
    df_brute = pd.DataFrame(brute_data)
    df_scan = pd.DataFrame(scan_data)

    df = pd.concat([df_normal, df_ddos, df_brute, df_scan], ignore_index=True)

    X = df[['connection_duration', 'packet_size_bytes', 'failed_login_attempts', 'protocol_type']]
    y = df['label']

    # 2. Train RandomForestClassifier Model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    # 3. Save Model to models/intrusion_model.pkl
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "intrusion_model.pkl")
    joblib.dump(model, model_path)

    print(f"[+] Intrusion Detection Model trained on {len(df)} samples.")
    print(f"[+] Model successfully saved to: {model_path}")

if __name__ == "__main__":
    train_and_save_intrusion_model()
