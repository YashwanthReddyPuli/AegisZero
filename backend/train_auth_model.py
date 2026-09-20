import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

def train_and_save_auth_model():
    np.random.seed(42)

    # 1. Generate Synthetic Login Dataset
    # Features: hour_of_day (0-23), failed_attempts_24h, distance_from_home_km

    # Normal baseline logins (e.g., campus logins in Bangalore)
    normal_count = 800
    normal_data = {
        'hour_of_day': np.random.randint(8, 23, normal_count),
        'failed_attempts_24h': np.random.choice([0, 0, 0, 0, 1], normal_count),
        'distance_from_home_km': np.random.uniform(0.1, 12.0, normal_count)
    }

    # Anomalous logins (e.g., 3 AM login after 5 failed attempts 450 km away)
    anom_count = 100
    anom_data = {
        'hour_of_day': np.random.choice([1, 2, 3, 4], anom_count),
        'failed_attempts_24h': np.random.randint(4, 15, anom_count),
        'distance_from_home_km': np.random.uniform(350.0, 1200.0, anom_count)
    }

    df_normal = pd.DataFrame(normal_data)
    df_anom = pd.DataFrame(anom_data)
    df = pd.concat([df_normal, df_anom], ignore_index=True)

    X = df[['hour_of_day', 'failed_attempts_24h', 'distance_from_home_km']]

    # 2. Train Isolation Forest Anomaly Model
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # 3. Save Model to models/auth_model.pkl
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "auth_model.pkl")
    joblib.dump(model, model_path)

    print(f"[+] Isolation Forest Auth Model trained on {len(df)} login records.")
    print(f"[+] Model successfully saved to: {model_path}")

if __name__ == "__main__":
    train_and_save_auth_model()
