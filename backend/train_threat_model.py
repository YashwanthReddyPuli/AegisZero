import os
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def train_and_save_model():
    # 1. Dataset of mock payloads (1 = Threat, 0 = Safe)
    data = [
        # Malicious Payloads (1)
        ("admin' --", 1),
        ("' OR 1=1 --", 1),
        ("UNION SELECT username, password FROM users --", 1),
        ("<script>alert('XSS')</script>", 1),
        ("<img src=x onerror=alert(1)>", 1),
        ("; cat /etc/passwd", 1),
        ("| ls -la", 1),
        ("../../../etc/shadow", 1),
        ("SELECT * FROM information_schema.tables", 1),
        ("DROP TABLE users; --", 1),
        ("<iframe src=\"javascript:alert('XSS')\"></iframe>", 1),
        ("eval(base64_decode('...'))", 1),
        ("system('rm -rf /')", 1),
        ("1' AND '1'='1", 1),
        ("<body onload=alert('hack')>", 1),

        # Benign Payloads (0)
        ("hello world", 0),
        ("john.doe@example.com", 0),
        ("Search for products in store", 0),
        ("Welcome to AegisAPI Security Center", 0),
        ("user_profile_data_123", 0),
        ("How to configure FastAPI with Next.js", 0),
        ("get_user_by_id?id=42", 0),
        ("standard_login_query_param", 0),
        ("contact_us_form_submission", 0),
        ("order_number_994820", 0),
        ("Python ML model training tutorial", 0),
        ("React frontend dashboard component", 0),
        ("FastAPI Uvicorn production server", 0),
        ("Securing modern web applications", 0)
    ]

    df = pd.DataFrame(data, columns=["payload", "label"])

    # 2. Extract features using TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), analyzer="char_wb")
    X = vectorizer.fit_transform(df["payload"])
    y = df["label"]

    # 3. Train Logistic Regression Model
    model = LogisticRegression(random_state=42)
    model.fit(X, y)

    # 4. Create models/ directory if it doesn't exist
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    # 5. Save model and vectorizer
    model_path = os.path.join(models_dir, "threat_model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    print(f"[+] Threat model successfully saved to: {model_path}")
    print(f"[+] Vectorizer successfully saved to: {vectorizer_path}")

if __name__ == "__main__":
    train_and_save_model()
