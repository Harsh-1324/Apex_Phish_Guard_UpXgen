```python
import os

import joblib
import numpy as np
import pandas as pd
import sklearn
import lightgbm

from flask import Flask, request, jsonify
from flask_cors import CORS
from huggingface_hub import hf_hub_download


# ============================================================
# VERSION INFORMATION
# ============================================================

print("SCIKIT-LEARN VERSION:", sklearn.__version__)
print("LIGHTGBM VERSION:", lightgbm.__version__)
print("NUMPY VERSION:", np.__version__)


# ============================================================
# HUGGING FACE CONFIGURATION
# ============================================================

HF_REPO_ID = "vision-forge-1324/phishing-model"

print("PhishGuard ML API starting...")
print("Hugging Face repository:", HF_REPO_ID)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

# Enable CORS for frontend/backend communication.
CORS(app)


# ============================================================
# MODEL PATHS
# ============================================================

EMAIL_MODEL_PATH = None
EMAIL_TFIDF_PATH = None
URL_MODEL_PATH = None


# ============================================================
# LAZY-LOADED MODELS
# ============================================================
#
# Models are NOT loaded when the application starts.
# They are downloaded/loaded only when the corresponding
# prediction endpoint is actually requested.
#
# This helps reduce startup memory usage.
# ============================================================

email_model = None
email_tfidf = None
url_model = None


# ============================================================
# SUSPICIOUS EMAIL TOKENS
# ============================================================

SUSPICIOUS_TOKENS = [
    "verify",
    "account",
    "password",
    "urgent",
    "click here",
    "security",
    "login",
    "confirm",
    "suspend",
    "update",
    "bank",
    "credit card",
    "reward",
    "limited",
    "action required",
    "invoice",
    "authenticate",
    "unusual activity",
]


# ============================================================
# MODEL FILE DOWNLOAD
# ============================================================

def get_model_path(filename):
    """
    Download a model from Hugging Face if it is not already
    available in the local Hugging Face cache.
    """

    print(f"Preparing model: {filename}")

    return hf_hub_download(
        repo_id=HF_REPO_ID,
        filename=filename,
    )


# ============================================================
# EMAIL MODEL LOADING
# ============================================================

def load_email_models():
    """
    Lazily download and load the email model and TF-IDF
    vectorizer.
    """

    global email_model
    global email_tfidf
    global EMAIL_MODEL_PATH
    global EMAIL_TFIDF_PATH

    if email_model is None:

        if EMAIL_MODEL_PATH is None:
            EMAIL_MODEL_PATH = get_model_path(
                "email_model.joblib"
            )

        print("Loading email model...")
        email_model = joblib.load(
            EMAIL_MODEL_PATH
        )

        print("Email model loaded.")

    if email_tfidf is None:

        if EMAIL_TFIDF_PATH is None:
            EMAIL_TFIDF_PATH = get_model_path(
                "email_tfidf.joblib"
            )

        print("Loading email TF-IDF...")
        email_tfidf = joblib.load(
            EMAIL_TFIDF_PATH
        )

        print("Email TF-IDF loaded.")


# ============================================================
# URL MODEL LOADING
# ============================================================

def load_url_model():
    """
    Lazily download and load the URL classification model.
    """

    global url_model
    global URL_MODEL_PATH

    if url_model is None:

        if URL_MODEL_PATH is None:
            URL_MODEL_PATH = get_model_path(
                "url_model.joblib"
            )

        print("Loading URL model...")

        url_model = joblib.load(
            URL_MODEL_PATH
        )

        print("URL model loaded.")


# ============================================================
# EMAIL EXPLANATION
# ============================================================

def explain_email(text):
    """
    Identify suspicious tokens present in the email.
    """

    text_lower = text.lower()

    matches = [
        word
        for word in SUSPICIOUS_TOKENS
        if word in text_lower
    ]

    if matches:

        return (
            "Suspicious keywords detected: "
            + ", ".join(
                sorted(set(matches))
            )
        )

    return "No obvious phishing tokens detected."


# ============================================================
# DETAILED EMAIL ANALYSIS
# ============================================================

def analyze_email(text):
    """
    Generate human-readable phishing indicators.
    """

    analysis_details = []

    text_lower = text.lower()

    # --------------------------------------------------------
    # Urgent language
    # --------------------------------------------------------

    urgent_words = [
        "urgent",
        "immediately",
        "action required",
        "limited time",
        "act now",
    ]

    for word in urgent_words:

        if word in text_lower:

            analysis_details.append(
                f'Contains urgent language: "{word}"'
            )

            break

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious_matches = [
        word
        for word in SUSPICIOUS_TOKENS
        if word in text_lower
    ]

    if suspicious_matches:

        unique_matches = sorted(
            set(suspicious_matches)
        )[:3]

        analysis_details.append(
            "Suspicious keywords detected: "
            + ", ".join(unique_matches)
        )

    # --------------------------------------------------------
    # Sensitive information requests
    # --------------------------------------------------------

    sensitive_requests = [
        "password",
        "credit card",
        "social security",
        "bank account",
        "verify your",
        "urgent",
        "loan",
        "repay",
        "payment",
    ]

    for req in sensitive_requests:

        if req in text_lower:

            analysis_details.append(
                f'Requests for sensitive information: "{req}"'
            )

            break

    # --------------------------------------------------------
    # Links / downloads / attachments
    # --------------------------------------------------------

    if (
        "click here" in text_lower
        or "download" in text_lower
        or "attachment" in text_lower
    ):

        analysis_details.append(
            "Contains request to click links or download attachments"
        )

    # --------------------------------------------------------
    # Potential impersonation
    # --------------------------------------------------------

    if (
        "from" in text_lower
        and any(
            word in text_lower
            for word in [
                "admin",
                "support",
                "security",
                "bank",
            ]
        )
    ):

        analysis_details.append(
            "Potential impersonation of legitimate organization"
        )

    # --------------------------------------------------------
    # Default response
    # --------------------------------------------------------

    if not analysis_details:

        analysis_details = [
            "No obvious phishing indicators detected"
        ]

    return analysis_details


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):
    """
    Extract the same structural URL features used by the
    trained URL model.

    IMPORTANT:
    The feature names and structure should remain identical
    to those used during model training.
    """

    features = {}
    analysis_details = []

    # --------------------------------------------------------
    # Length
    # --------------------------------------------------------

    features["url_length"] = len(url)

    # --------------------------------------------------------
    # Domain
    # --------------------------------------------------------

    url_parts = url.split("/")

    domain_part = (
        url_parts[2]
        if len(url_parts) > 2
        else ""
    )

    features["domain_length"] = len(
        domain_part
    )

    # --------------------------------------------------------
    # Character counts
    # --------------------------------------------------------

    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_at"] = url.count("@")
    features["num_question"] = url.count("?")

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    has_https = url.lower().startswith(
        "https"
    )

    features["has_https"] = (
        1 if has_https else 0
    )

    if not has_https:

        analysis_details.append(
            "No HTTPS encryption"
        )

    # --------------------------------------------------------
    # Suspicious extensions
    # --------------------------------------------------------

    suspicious_extensions = [
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".info",
        ".biz",
        ".pw",
    ]

    domain_lower = domain_part.lower()

    for ext in suspicious_extensions:

        if domain_lower.endswith(ext):

            analysis_details.append(
                f"Suspicious domain extension ({ext})"
            )

            break

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    if domain_part:

        domain_without_port = (
            domain_part.split(":")[0]
        )

        parts = domain_without_port.split(".")

        if (
            len(parts) == 4
            and all(
                part.isdigit()
                for part in parts
            )
            and all(
                0 <= int(part) <= 255
                for part in parts
            )
        ):

            analysis_details.append(
                "URL uses IP address instead of domain name"
            )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious_keywords = [
        "verify",
        "confirm",
        "login",
        "update",
        "account",
    ]

    matching_keywords = [
        word
        for word in suspicious_keywords
        if word in url.lower()
    ]

    features["suspicious_keywords"] = len(
        matching_keywords
    )

    if matching_keywords:

        analysis_details.append(
            "Contains suspicious keywords: "
            + ", ".join(
                matching_keywords
            )
        )

    # --------------------------------------------------------
    # Long URL
    # --------------------------------------------------------

    if features["url_length"] > 75:

        analysis_details.append(
            "Unusually long URL"
        )

    # --------------------------------------------------------
    # Multiple hyphens
    # --------------------------------------------------------

    if features["num_hyphens"] > 2:

        analysis_details.append(
            "Multiple hyphens in URL (subdomain obfuscation)"
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if features["num_at"] > 0:

        analysis_details.append(
            "Contains @ symbol (credential spoofing indicator)"
        )

    return features, analysis_details


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "PhishGuard ML API is ready",
        "models": [
            "email (soft voting ensemble)",
            "url (soft voting ensemble)",
        ],
    })


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.route("/", methods=["GET"])
def root():

    return jsonify({
        "service": "PhishGuard ML API",
        "status": "running",
        "endpoints": [
            "/health",
            "/predict",
        ],
    })


# ============================================================
# PREDICTION ENDPOINT
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    # --------------------------------------------------------
    # Validate JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error": "No JSON data received"
        }), 400

    # --------------------------------------------------------
    # Validate required fields
    # --------------------------------------------------------

    if (
        "input" not in data
        or "type" not in data
    ):

        return jsonify({
            "error": "Request must contain 'input' and 'type'"
        }), 400

    input_text = str(
        data["input"]
    ).strip()

    target_type = str(
        data["type"]
    ).lower().strip()

    # --------------------------------------------------------
    # Empty input
    # --------------------------------------------------------

    if not input_text:

        return jsonify({
            "error": "Input cannot be empty"
        }), 400

    # ========================================================
    # EMAIL PREDICTION
    # ========================================================

    if target_type == "email":

        load_email_models()

        # TF-IDF transformation
        input_tfidf = email_tfidf.transform(
            [input_text]
        )

        # Prediction
        prediction = email_model.predict(
            input_tfidf
        )[0]

        # Probability
        proba = email_model.predict_proba(
            input_tfidf
        )

        confidence = float(
            np.max(proba) * 100
        )

        # Explanation
        details = explain_email(
            input_text
        )

        analysis_details = analyze_email(
            input_text
        )

    # ========================================================
    # URL PREDICTION
    # ========================================================

    elif target_type == "url":

        load_url_model()

        # Extract features
        url_features, analysis_details = (
            extract_url_features(
                input_text
            )
        )

        # Keep feature structure identical
        # to the trained model.
        url_features_df = pd.DataFrame(
            [url_features]
        )

        # Prediction
        prediction = url_model.predict(
            url_features_df
        )[0]

        # Probability
        proba = url_model.predict_proba(
            url_features_df
        )

        confidence = float(
            np.max(proba) * 100
        )

        details = (
            "URL analyzed using structural features "
            "(length, special characters, domain structure) "
            "for phishing pattern detection."
        )

        if not analysis_details:

            analysis_details = [
                "No suspicious indicators detected"
            ]

    # ========================================================
    # INVALID TYPE
    # ========================================================

    else:

        return jsonify({
            "error": (
                "Invalid type. "
                "Use 'email' or 'url'."
            )
        }), 400

    # ========================================================
    # API RESPONSE
    # ========================================================

    return jsonify({

        "type": target_type,

        "input": input_text,

        "isPhishing": bool(
            prediction
        ),

        "confidence": round(
            confidence,
            1
        ),

        "reasons": [
            details
        ],

        "details": details,

        "analysisDetails": analysis_details,
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def request_too_large(error):

    return jsonify({
        "error": "Request payload is too large."
    }), 413


@app.errorhandler(500)
def internal_error(error):

    print(
        "Internal server error:",
        error
    )

    return jsonify({
        "error": "Internal server error."
    }), 500


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
```
