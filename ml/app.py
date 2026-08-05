import os
import re
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / 'models'
EMAIL_MODEL_PATH = MODEL_DIR / 'email_model.joblib'
EMAIL_TFIDF_PATH = MODEL_DIR / 'email_tfidf.joblib'
URL_MODEL_PATH = MODEL_DIR / 'url_model.joblib'

app = Flask(__name__)
CORS(app)

email_model = joblib.load(EMAIL_MODEL_PATH)
email_tfidf = joblib.load(EMAIL_TFIDF_PATH)
url_model = joblib.load(URL_MODEL_PATH)
print('✓ All models loaded successfully')

SUSPICIOUS_TOKENS = [
    'verify', 'account', 'password', 'urgent', 'click here', 'security',
    'login', 'confirm', 'suspend', 'update', 'bank', 'credit card',
    'reward', 'limited', 'action required', 'invoice', 'authenticate',
    'unusual activity'
]


def extract_url_features(url):
    """Extract simple features from URLs that indicate phishing."""
    features = {}
    analysis_details = []
    
    # Length-based features
    features['url_length'] = len(url)
    features['domain_length'] = len(url.split('/')[2]) if len(url.split('/')) > 2 else 0
    
    # Character counts (indicators of suspicious URLs)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')  # @ symbol is suspicious
    features['num_question'] = url.count('?')
    
    # Security indicator
    has_https = url.startswith('https')
    features['has_https'] = 1 if has_https else 0
    if not has_https:
        analysis_details.append('No HTTPS encryption')
    
    # Domain analysis
    domain_part = url.split('/')[2] if len(url.split('/')) > 2 else ''
    suspicious_extensions = ['.xyz', '.tk', '.ml', '.ga', '.info', '.biz', '.pw']
    for ext in suspicious_extensions:
        if domain_part.endswith(ext):
            analysis_details.append(f'Suspicious domain extension ({ext})')
            break
    
    # Check for IP address (common in phishing)
    if domain_part and all(part.isdigit() or part == '.' for part in domain_part):
        analysis_details.append('URL uses IP address instead of domain name')
    
    # Suspicious keywords
    suspicious = ['verify', 'confirm', 'login', 'update', 'account']
    matching_keywords = [word for word in suspicious if word in url.lower()]
    features['suspicious_keywords'] = len(matching_keywords)
    if matching_keywords:
        analysis_details.append(f'Contains suspicious keywords: {", ".join(matching_keywords)}')
    
    # URL length (very long URLs can be suspicious)
    if features['url_length'] > 75:
        analysis_details.append('Unusually long URL')
    
    # Multiple hyphens (subdomain obfuscation)
    if features['num_hyphens'] > 2:
        analysis_details.append('Multiple hyphens in URL (subdomain obfuscation)')
    
    # @ symbol (very suspicious)
    if features['num_at'] > 0:
        analysis_details.append('Contains @ symbol (credential spoofing indicator)')
    
    return features, analysis_details


def explain_email(text):
    tokens = text.lower().split()
    matches = [token for token in tokens if any(word in token for word in SUSPICIOUS_TOKENS)]
    if matches:
        return 'Suspicious keywords detected: ' + ', '.join(sorted(set(matches)))
    return 'No obvious phishing tokens detected.'


def analyze_email(text):
    """Extract detailed analysis details from email text."""
    analysis_details = []
    text_lower = text.lower()
    
    # Check for urgent language
    urgent_words = ['urgent', 'immediately', 'action required', 'limited time', 'act now']
    for word in urgent_words:
        if word in text_lower:
            analysis_details.append(f'Contains urgent language: "{word}"')
            break
    
    # Check for suspicious keywords
    tokens = text_lower.split()
    suspicious_matches = [token for token in tokens if any(word in token for word in SUSPICIOUS_TOKENS)]
    if suspicious_matches:
        unique_matches = sorted(set(suspicious_matches))[:3]  # Limit to 3
        analysis_details.append(f'Suspicious keywords detected: {", ".join(unique_matches)}')
    
    # Check for requests for sensitive information
    sensitive_requests = ['password', 'credit card', 'social security', 'bank account', 'verify your','urgent','loan','repay','payment']
    for req in sensitive_requests:
        if req in text_lower:
            analysis_details.append(f'Requests for sensitive information: "{req}"')
            break
    
    # Check for suspicious links or attachments implied
    if 'click here' in text_lower or 'download' in text_lower or 'attachment' in text_lower:
        analysis_details.append('Contains request to click links or download attachments')
    
    # Check for impersonation
    if 'from' in text_lower and any(word in text_lower for word in ['admin', 'support', 'security', 'bank']):
        analysis_details.append('Potential impersonation of legitimate organization')
    
    if not analysis_details:
        analysis_details = ['No obvious phishing indicators detected']
    
    return analysis_details


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'PhishGuard ML API is ready',
        'models': ['email (soft voting ensemble)', 'url (soft voting ensemble)']
    })


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    input_text = str(data['input']).strip()
    target_type = data['type']

    if target_type == 'email':
        input_tfidf = email_tfidf.transform([input_text]).toarray()
        prediction = email_model.predict(input_tfidf)[0]
        proba = email_model.predict_proba(input_tfidf)
        confidence = float(np.max(proba) * 100)
        details = explain_email(input_text)
        analysis_details = analyze_email(input_text)
    elif target_type == 'url':
        url_features, analysis_details = extract_url_features(input_text)
        url_features_df = pd.DataFrame([url_features])
        prediction = url_model.predict(url_features_df)[0]
        proba = url_model.predict_proba(url_features_df)
        confidence = float(np.max(proba) * 100)
        details = 'URL analyzed using structural features (length, special chars, subdomains) for phishing pattern detection.'
        if not analysis_details:
            analysis_details = ['No suspicious indicators detected']

    return jsonify({
        'type': target_type,
        'input': input_text,
        'isPhishing': bool(prediction),
        'confidence': round(confidence, 1),
        'reasons': [details],
        'details': details,
        'analysisDetails': analysis_details,
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
