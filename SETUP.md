# PhishGuard - Setup Instructions

This is a full-stack phishing detection application. Follow these steps to set it up and run it locally.

## Prerequisites

Make sure you have installed:
- **Node.js** (v14 or higher) - [Download](https://nodejs.org/)
- **Python** (v3.8 or higher) - [Download](https://www.python.org/)

## Setup Steps

### Step 1: Install Frontend Dependencies

```bash
cd frontend
npm install
cd ..
```

### Step 2: Install Backend Dependencies

```bash
cd backend
npm install
cd ..
```

### Step 3: Install Python Dependencies

```bash
cd ml
python -m pip install -r requirements.txt
cd ..
```

### Step 4: Train ML Models

The machine learning models must be trained before running the API. This generates the model files needed for predictions.

```bash
cd ml
python train.py
cd ..
```

This will create three model files in the `ml/models/` directory:
- `email_model.joblib` - Trained model for email phishing detection
- `url_model.joblib` - Trained model for URL phishing detection
- `url_columns.joblib` - Feature columns mapping for URL model

## Running the Application

You need to run **three separate terminals** to start all services:

### Terminal 1: Start the Python Flask ML API

```bash
cd ml
python app.py
```

The API will run on `http://localhost:5000`

### Terminal 2: Start the Node.js Backend Proxy

```bash
cd backend
npm start
```

The backend will run on `http://localhost:3001`

### Terminal 3: Start the React Frontend

```bash
cd frontend
npm start
```

The frontend will open automatically at `http://localhost:3000`

## Project Architecture

- **Frontend** (`frontend/`) - React.js web interface for uploading emails and URLs
- **Backend** (`backend/`) - Node.js Express server that proxies requests to the ML API and manages history
- **ML** (`ml/`) - Python Flask API with TF-IDF and Random Forest models for phishing detection

## Database

The application uses SQLite for storing analysis history. The database file (`phishguard.db`) is created automatically in the project root directory when you first run the backend.

## Troubleshooting

**Port already in use?**
- ML API (5000): `python app.py --port 5001`
- Backend (3001): `PORT=3002 npm start`
- Frontend (3000): `PORT=3001 npm start`

**Models not found?**
- Make sure you ran `python train.py` from the `ml/` directory

**Can't connect to backend?**
- Check that all three services are running
- Verify localhost ports are correct
- Check browser console (F12) for CORS errors

## Sample Data

If no CSV files are provided in `ml/data/`, the training script uses sample data to create working models. For better accuracy, you can:
- Place `phishing_emails.csv` in `ml/data/` with columns: `text`, `label`
- Place `phishing_urls.csv` in `ml/data/` with columns: `url`, `label`

Where `label` is 1 for phishing and 0 for legitimate content.

## Next Steps

- Test the application with sample phishing emails and URLs provided in the UI
- Check the "History" tab to see past analyses
- Modify the ML models by updating training data or hyperparameters in `ml/train.py`
  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
in E drive then editinthis then ediinthis
  {{first backend then ml then frontend in seperate terminals and in the same directory 


 1st terminal command like below (also take help from above mainly):
PS E:\editinthis> cd editinthis 
PS E:\editinthis\editinthis> cd backend
>> npm start

 2nd terminal command:
PS E:\editinthis> cd editinthis
PS E:\editinthis\editinthis> cd ml
>> python app.py

 3rd terminal command: 
PS E:\editinthis> cd editinthis
PS E:\editinthis\editinthis> cd frontend
>> npm start}}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

also for f1 score and all click on train.py and then run through triangle button

--------------------------------------------------------------------
PS E:\editinthis> & "C:\Program Files\Python314\python.exe" e:/editinthis/editinthis/ml/train.py
============================================================
Training PhishGuard Models (Soft Voting Ensemble)
============================================================

--- Building Email Model (Soft Voting Ensemble) ---

  Individual Models:
  Logistic Regression: Accuracy=0.9758, Precision=1.0000, Recall=0.8188, F1=0.9004
  Random Forest: Accuracy=0.9785, Precision=0.9921, Recall=0.8456, F1=0.9130
  LightGBM: Accuracy=0.9731, Precision=0.9474, Recall=0.8456, F1=0.8936

  Ensemble:
  Soft Voting Ensemble: Accuracy=0.9794, Precision=1.0000, Recall=0.8456, F1=0.9164
✓ Email model saved

--- Building URL Model (Soft Voting Ensemble) ---
  Extracting URL features...

  Ensemble (test set):
  Soft Voting Ensemble: Accuracy=0.8289, Precision=0.7840, Recall=0.5508, F1=0.6470
--------------------------------------------------------------------------------------------