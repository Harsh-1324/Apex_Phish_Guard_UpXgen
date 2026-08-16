# PhishGuard

A full-stack phishing detection web application with:

- React frontend with alert popups and explanation panels
- Node.js backend proxy to a Python Flask ML API
- Local SQLite storage for history, no PostgreSQL required
- Python ML models using TF-IDF + Logistic Regression for email analysis
- Random Forest URL detection with extracted URL features

## Folder structure

- `frontend` — React app source and build files
- `backend` — Node.js Express proxy server
- `ml` — Python training and Flask API


