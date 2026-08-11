import os
import threading

import joblib
import numpy as np
import sklearn
import lightgbm

from flask import Flask, request, jsonify
from flask_cors import CORS
from huggingface_hub import hf_hub_download

# ============================================================

# VERSION INFORMATION

# ============================================================

print("SCIKIT-LEARN VERSION:", sklearn.**version**)
print("LIGHTGBM VERSION:", lightgbm.**version**)
print("NUMPY VERSION:", np.**version**)

# ============================================================

# FLASK APPLICATION

# ============================================================

app = Flask(**name**)

# Allow frontend/backend communication

CORS(app)

# ============================================================

# CONFIGURATION

# ============================================================

HF_REPO_ID = "vision-forge-1324/phishing-model"

PORT = int(os.environ.get("PORT", 5000))

# ============================================================

# MODEL STATE

# ============================================================

# Model objects are loaded only when required.

email_model = None
email_tfidf = None
url_model = None

# Downloaded model paths

email_model_path = None
email_tfidf_path = None
url_model_path = None

# Locks prevent multiple Gunicorn requests from loading

# the same model simultaneously.

email_model_lock = threading.Lock()
url_model_lock = threading.Lock()

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
"unusual activity"
]

# ============================================================

# MODEL DOWNLOAD FUNCTIONS

# ============================================================

def get_email_model_path():
"""
Download the email classification model from Hugging Face
only when it is actually required.
"""

```
global email_model_path

if email_model_path is None:
    print("Downloading email_model.joblib from Hugging Face...")

    email_model_path = hf_hub_download(
        repo_id=HF_REPO_ID,
        filename="email_model.joblib"
    )

    print("Email model downloaded successfully.")

return email_model_path
```

def get_email_tfidf_path():
"""
Download the email TF-IDF vectorizer only when required.
"""

```
global email_tfidf_path

if email_tfidf_path is None:
    print("Downloading email_tfidf.joblib from Hugging Face...")

    email_tfidf_path = hf_hub_download(
        repo_id=HF_REPO_ID,
        filename="email_tfidf.joblib"
    )

    print("Email TF-IDF downloaded successfully.")

return email_tfidf_path
```

def get_url_model_path():
"""
Download the URL classification model only when required.
"""

```
global url_model_path

if url_model_path is None:
    print("Downloading url_model.joblib from Hugging Face...")

    url_model_path = hf_hub_download(
        repo_id=HF_REPO_ID,
        filename="url_model.joblib"
    )

    print("URL model downloaded successfully.")

return url_model_path
```

# ============================================================

# MODEL LOADING

# ============================================================

def load_email_models():
"""
Load the email model and TF-IDF vectorizer into memory.

```
Thread-safe lazy loading prevents unnecessary memory usage
during application startup.
"""

global email_model, email_tfidf

if email_model is None or email_tfidf is None:

    with email_model_lock:

        if email_model is None:

            print("Loading email model...")

            email_model = joblib.load(
                get_email_model_path()
            )

            print("Email model loaded.")

        if email_tfidf is None:

            print("Loading email TF-IDF vectorizer...")

            email_tfidf = joblib.load(
                get_email_tfidf_path()
            )

            print("Email TF-IDF vectorizer loaded.")
```

def load_url_model():
"""
Load the URL model into memory.

```
Thread-safe lazy loading prevents unnecessary memory usage
until URL scanning is actually requested.
"""

global url_model

if url_model is None:

    with url_model_lock:

        if url_model is None:

            print("Loading URL model...")

            url_model = joblib.load(
                get_url_model_path()
            )

            print("URL model loaded.")
```

# ============================================================

# URL FEATURE EXTRACTION

# ============================================================

def extract_url_features(url):
"""
Extract the same structural features used during
URL model training.

```
IMPORTANT:
The feature names and order must remain compatible
with the trained model.
"""

analysis_details = []

# --------------------------------------------------------
# Basic URL parsing
# --------------------------------------------------------

parts = url.split("/")

domain_part = ""

if len(parts) > 2:
    domain_part = parts[2]

url_lower = url.lower()
domain_lower = domain_part.lower()

# --------------------------------------------------------
# Features
# --------------------------------------------------------

url_length = len(url)

domain_length = len(domain_part)

num_dots = url.count(".")

num_hyphens = url.count("-")

num_slashes = url.count("/")

num_at = url.count("@")

num_question = url.count("?")

has_https = 1 if url_lower.startswith("https") else 0

suspicious_keywords = [
    "verify",
    "confirm",
    "login",
    "update",
    "account"
]

matching_keywords = [
    word
    for word in suspicious_keywords
    if word in url_lower
]

suspicious_keyword_count = len(
    matching_keywords
)

# --------------------------------------------------------
# Feature dictionary
# --------------------------------------------------------

features = {
    "url_length": url_length,
    "domain_length": domain_length,
    "num_dots": num_dots,
    "num_hyphens": num_hyphens,
    "num_slashes": num_slashes,
    "num_at": num_at,
    "num_question": num_question,
    "has_https": has_https,
    "suspicious_keywords": suspicious_keyword_count
}

# --------------------------------------------------------
# HTTPS analysis
# --------------------------------------------------------

if not has_https:

    analysis_details.append(
        "No HTTPS encryption"
    )

# --------------------------------------------------------
# Suspicious domain extensions
# --------------------------------------------------------

suspicious_extensions = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".info",
    ".biz",
    ".pw"
]

for extension in suspicious_extensions:

    if domain_lower.endswith(extension):

        analysis_details.append(
            f"Suspicious domain extension ({extension})"
        )

        break

# --------------------------------------------------------
# IP address detection
# --------------------------------------------------------

if domain_part:

    ip_parts = domain_part.split(".")

    if (
        len(ip_parts) == 4
        and all(part.isdigit() for part in ip_parts)
    ):

        analysis_details.append(
            "URL uses IP address instead of domain name"
        )

# --------------------------------------------------------
# Suspicious keywords
# --------------------------------------------------------

if matching_keywords:

    analysis_details.append(
        "Contains suspicious keywords: "
        + ", ".join(matching_keywords)
    )

# --------------------------------------------------------
# Long URL
# --------------------------------------------------------

if url_length > 75:

    analysis_details.append(
        "Unusually long URL"
    )

# --------------------------------------------------------
# Multiple hyphens
# --------------------------------------------------------

if num_hyphens > 2:

    analysis_details.append(
        "Multiple hyphens in URL (subdomain obfuscation)"
    )

# --------------------------------------------------------
# @ symbol
# --------------------------------------------------------

if num_at > 0:

    analysis_details.append(
        "Contains @ symbol (credential spoofing indicator)"
    )

return features, analysis_details
```

# ============================================================

# EMAIL EXPLANATION

# ============================================================

def explain_email(text):
"""
Generate a short explanation based on suspicious
phishing-related tokens.
"""

```
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
```

# ============================================================

# DETAILED EMAIL ANALYSIS

# ============================================================

def analyze_email(text):
"""
Generate human-readable indicators explaining
why an email may be suspicious.
"""

```
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

for request_word in sensitive_requests:

    if request_word in text_lower:

        analysis_details.append(
            f'Requests for sensitive information: "{request_word}"'
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
```

# ============================================================

# ROOT ENDPOINT

# ============================================================

@app.route("/", methods=["GET"])
def root():

```
return jsonify({
    "service": "PhishGuard ML API",
    "status": "online",
    "version": "1.0",
    "endpoints": [
        "/",
        "/health",
        "/predict"
    ]
})
```

# ============================================================

# HEALTH CHECK

# ============================================================

@app.route("/health", methods=["GET"])
def health():

```
return jsonify({
    "status": "PhishGuard ML API is ready",
    "models": {
        "email": "lazy-loaded",
        "url": "lazy-loaded"
    }
})
```

# ============================================================

# PREDICTION ENDPOINT

# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

```
try:

    # ----------------------------------------------------
    # JSON validation
    # ----------------------------------------------------

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "error": "No JSON data received"
        }), 400

    if "input" not in data:

        return jsonify({
            "error": "Request must contain 'input'"
        }), 400

    if "type" not in data:

        return jsonify({
            "error": "Request must contain 'type'"
        }), 400

    input_text = str(
        data["input"]
    ).strip()

    target_type = str(
        data["type"]
    ).lower().strip()

    if not input_text:

        return jsonify({
            "error": "Input cannot be empty"
        }), 400

    # ====================================================
    # EMAIL PREDICTION
    # ====================================================

    if target_type == "email":

        load_email_models()

        # Transform email using the trained TF-IDF vectorizer
        input_tfidf = email_tfidf.transform(
            [input_text]
        )

        prediction = email_model.predict(
            input_tfidf
        )[0]

        probabilities = email_model.predict_proba(
            input_tfidf
        )

        confidence = float(
            np.max(probabilities) * 100
        )

        details = explain_email(
            input_text
        )

        analysis_details = analyze_email(
            input_text
        )

    # ====================================================
    # URL PREDICTION
    # ====================================================

    elif target_type == "url":

        load_url_model()

        url_features, analysis_details = (
            extract_url_features(input_text)
        )

        # IMPORTANT:
        # Use a list-of-dicts instead of pandas DataFrame.
        # This avoids loading pandas just for one prediction.
        #
        # If your trained LightGBM model requires a DataFrame
        # because it was trained with feature names, the model
        # may require pandas here. In that case, keep pandas
        # in requirements.txt and replace this section with:
        #
        # url_features_input = pd.DataFrame([url_features])

        prediction = url_model.predict(
            [list(url_features.values())]
        )[0]

        probabilities = url_model.predict_proba(
            [list(url_features.values())]
        )

        confidence = float(
            np.max(probabilities) * 100
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

    # ====================================================
    # INVALID TYPE
    # ====================================================

    else:

        return jsonify({
            "error": "Invalid type. Use 'email' or 'url'."
        }), 400

    # ====================================================
    # RESPONSE
    # ====================================================

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

except Exception as error:

    print(
        "Prediction error:",
        repr(error)
    )

    return jsonify({
        "error": "Prediction failed",
        "message": str(error)
    }), 500
```

# ============================================================

# APPLICATION STARTUP

# ============================================================

if **name** == "**main**":

```
print(
    f"Starting PhishGuard ML API on port {PORT}..."
)

app.run(
    host="0.0.0.0",
    port=PORT,
    debug=False
)
```
