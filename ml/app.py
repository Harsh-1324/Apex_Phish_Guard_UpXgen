import os

from flask import Flask, request, jsonify
from flask_cors import CORS
from huggingface_hub import hf_hub_download

import joblib
import numpy as np
import pandas as pd

import sklearn
import lightgbm
import numpy

print("SCIKIT-LEARN VERSION:", sklearn.__version__)
print("LIGHTGBM VERSION:", lightgbm.__version__)
print("NUMPY VERSION:", numpy.__version__)

# ============================================================
# Hugging Face Model Configuration
# ============================================================

HF_REPO_ID = "vision-forge-1324/phishing-model"

print("Downloading/loading ML models from Hugging Face...")


# ============================================================
# Download Models from Hugging Face
# ============================================================

EMAIL_MODEL_PATH = hf_hub_download(
    repo_id=HF_REPO_ID,
    filename="email_model.joblib"
)

EMAIL_TFIDF_PATH = hf_hub_download(
    repo_id=HF_REPO_ID,
    filename="email_tfidf.joblib"
)

URL_MODEL_PATH = hf_hub_download(
    repo_id=HF_REPO_ID,
    filename="url_model.joblib"
)


# ============================================================
# Flask App
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# Lazy-Loading Model Variables
# ============================================================

email_model = None
email_tfidf = None
url_model = None
print("Models configured for lazy loading to optimize memory usage.")


def load_email_models():
    global email_model, email_tfidf
    if email_model is None:
        print("Loading email model...")
        email_model = joblib.load(EMAIL_MODEL_PATH)
    if email_tfidf is None:
        print("Loading email TF-IDF...")
        email_tfidf = joblib.load(EMAIL_TFIDF_PATH)


def load_url_model():
    global url_model
    if url_model is None:
        print("Loading URL model...")
        url_model = joblib.load(URL_MODEL_PATH)


# ============================================================
# Suspicious Email Tokens
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
    "unusual activity"
]


# ============================================================
# URL Feature Extraction
# ============================================================

def extract_url_features(url):
    """Extract simple features from URLs that indicate phishing."""

    features = {}
    analysis_details = []

    # --------------------------------------------------------
    # Length-based features
    # --------------------------------------------------------

    features["url_length"] = len(url)

    features["domain_length"] = (
        len(url.split("/")[2])
        if len(url.split("/")) > 2
        else 0
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
    # HTTPS check
    # --------------------------------------------------------

    has_https = url.lower().startswith("https")

    features["has_https"] = 1 if has_https else 0

    if not has_https:
        analysis_details.append("No HTTPS encryption")

    # --------------------------------------------------------
    # Domain analysis
    # --------------------------------------------------------

    domain_part = (
        url.split("/")[2]
        if len(url.split("/")) > 2
        else ""
    )

    suspicious_extensions = [
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".info",
        ".biz",
        ".pw"
    ]

    for ext in suspicious_extensions:
        if domain_part.lower().endswith(ext):
            analysis_details.append(
                f"Suspicious domain extension ({ext})"
            )
            break

    # --------------------------------------------------------
    # IP address check
    # --------------------------------------------------------

    if domain_part:
        parts = domain_part.split(".")

        if (
            len(parts) == 4
            and all(part.isdigit() for part in parts)
        ):
            analysis_details.append(
                "URL uses IP address instead of domain name"
            )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious = [
        "verify",
        "confirm",
        "login",
        "update",
        "account"
    ]

    matching_keywords = [
        word
        for word in suspicious
        if word in url.lower()
    ]

    features["suspicious_keywords"] = len(
        matching_keywords
    )

    if matching_keywords:
        analysis_details.append(
            f'Contains suspicious keywords: {", ".join(matching_keywords)}'
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
# Email Explanation
# ============================================================

def explain_email(text):

    text_lower = text.lower()

    matches = [
        word
        for word in SUSPICIOUS_TOKENS
        if word in text_lower
    ]

    if matches:
        return (
            "Suspicious keywords detected: "
            + ", ".join(sorted(set(matches)))
        )

    return "No obvious phishing tokens detected."


# ============================================================
# Detailed Email Analysis
# ============================================================

def analyze_email(text):
    """Extract detailed analysis details from email text."""

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
        "act now"
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
        "payment"
    ]

    for req in sensitive_requests:

        if req in text_lower:

            analysis_details.append(
                f'Requests for sensitive information: "{req}"'
            )

            break

    # --------------------------------------------------------
    # Links / attachments
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
    # Impersonation
    # --------------------------------------------------------

    if (
        "from" in text_lower
        and any(
            word in text_lower
            for word in [
                "admin",
                "support",
                "security",
                "bank"
            ]
        )
    ):
        analysis_details.append(
            "Potential impersonation of legitimate organization"
        )

    # --------------------------------------------------------
    # No indicators
    # --------------------------------------------------------

    if not analysis_details:
        analysis_details = [
            "No obvious phishing indicators detected"
        ]

    return analysis_details


# ============================================================
# Health Check Endpoint
# ============================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "PhishGuard ML API is ready",
        "models": [
            "email (soft voting ensemble)",
            "url (soft voting ensemble)"
        ]
    })


# ============================================================
# Prediction Endpoint
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json(force=True)

    if not data:
        return jsonify({
            "error": "No JSON data received"
        }), 400

    if "input" not in data or "type" not in data:
        return jsonify({
            "error": "Request must contain 'input' and 'type'"
        }), 400

    input_text = str(
        data["input"]
    ).strip()

    target_type = data["type"]

    # ========================================================
    # Email Prediction
    # ========================================================

    if target_type == "email":

        load_email_models()

        input_tfidf = email_tfidf.transform(
            [input_text]
        ).toarray()

        prediction = email_model.predict(
            input_tfidf
        )[0]

        proba = email_model.predict_proba(
            input_tfidf
        )

        confidence = float(
            np.max(proba) * 100
        )

        details = explain_email(
            input_text
        )

        analysis_details = analyze_email(
            input_text
        )

    # ========================================================
    # URL Prediction
    # ========================================================

    elif target_type == "url":

        load_url_model()

        url_features, analysis_details = (
            extract_url_features(input_text)
        )

        url_features_df = pd.DataFrame(
            [url_features]
        )

        prediction = url_model.predict(
            url_features_df
        )[0]

        proba = url_model.predict_proba(
            url_features_df
        )

        confidence = float(
            np.max(proba) * 100
        )

        details = (
            "URL analyzed using structural features "
            "(length, special chars, subdomains) "
            "for phishing pattern detection."
        )

        if not analysis_details:
            analysis_details = [
                "No suspicious indicators detected"
            ]

    # ========================================================
    # Invalid Type
    # ========================================================

    else:

        return jsonify({
            "error": "Invalid type. Use 'email' or 'url'."
        }), 400

    # ========================================================
    # Response
    # ========================================================

    return jsonify({

        "type": target_type,

        "input": input_text,

        "isPhishing": bool(prediction),

        "confidence": round(
            confidence,
            1
        ),

        "reasons": [
            details
        ],

        "details": details,

        "analysisDetails": analysis_details

    })


# ============================================================
# Run Flask Application
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