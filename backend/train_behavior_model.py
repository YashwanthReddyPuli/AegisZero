import os
import pandas as pd
import numpy as np
import joblib
from sklearn.svm import OneClassSVM

def train_and_save_behavior_model():
    np.random.seed(42)

    # 1. Generate Synthetic System Metrics Dataset
    # Features: requests_per_minute, data_transfer_mb, error_rate_percentage

    # Normal baseline server traffic (800 samples)
    normal_count = 800
    normal_data = {
        'requests_per_minute': np.random.uniform(10.0, 50.0, normal_count),
        'data_transfer_mb': np.random.uniform(1.0, 5.0, normal_count),
        'error_rate_percentage': np.random.uniform(0.0, 2.0, normal_count)
    }

    # Outlier / Anomaly traffic (e.g., rogue bot, data exfiltration)
    outlier_count = 100
    outlier_data = {
        'requests_per_minute': np.random.uniform(2000.0, 8000.0, outlier_count),
        'data_transfer_mb': np.random.uniform(200.0, 800.0, outlier_count),
        'error_rate_percentage': np.random.uniform(10.0, 25.0, outlier_count)
    }

    df_normal = pd.DataFrame(normal_data)
    df_outlier = pd.DataFrame(outlier_data)

    # Train One-Class SVM strictly on normal baseline dataset
    X_train = df_normal[['requests_per_minute', 'data_transfer_mb', 'error_rate_percentage']]

    # 2. Train OneClassSVM Model
    model = OneClassSVM(nu=0.05, kernel="rbf", gamma="scale")
    model.fit(X_train)

    # 3. Save Model to models/behavior_model.pkl
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "behavior_model.pkl")
    joblib.dump(model, model_path)

    print(f"[+] OneClassSVM Behavior Anomaly Model trained on {len(df_normal)} normal samples.")
    print(f"[+] Model successfully saved to: {model_path}")

if __name__ == "__main__":
    train_and_save_behavior_model()
