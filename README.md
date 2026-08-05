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

## Quick start

1. Install the frontend dependencies:

```bash
cd frontend
npm install
```

2. Install the backend dependencies:

```bash
cd ../backend
npm install
```

3. Install the Python ML dependencies:

```bash
cd ../ml
python -m pip install -r requirements.txt
```

4. Train the models:

```bash
python train.py
```

5. Start the Flask ML API:

```bash
python app.py
```

6. Start the Node.js backend:

```bash
cd ../backend
npm start
```

7. Start the React frontend:

```bash
cd ../frontend
npm start
```

Open `http://localhost:3000` to view PhishGuard.

## Dataset notes

- This project uses sample training data when actual `ml/data` CSV files are not present.
- For Kaggle-style datasets, place them under `ml/data/phishing_emails.csv` and `ml/data/phishing_urls.csv`.
- Email dataset should include `text` and `label` columns.
- URL dataset should include `url` and `label` columns.
