import pandas as pd
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import lightgbm as lgb
import joblib
import re

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / 'models'
MODEL_DIR.mkdir(parents=True, exist_ok=True)

EMAIL_DATA = ROOT / 'data' / 'mail_data.csv'
URL_DATA = ROOT / 'data' / 'phishing_site_urls.csv'


def evaluate_model(y_true, y_pred, model_name):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='binary')
    recall = recall_score(y_true, y_pred, average='binary')
    f1 = f1_score(y_true, y_pred, average='binary')
    print(f'  {model_name}: Accuracy={accuracy:.4f}, Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}')


def build_email_model():
    print('\n--- Building Email Model (Soft Voting Ensemble) ---')
    email_df = pd.read_csv(EMAIL_DATA)
    email_df = email_df.rename(columns={'Message': 'text', 'Category': 'label'})
    email_df['label'] = email_df['label'].map({'spam': 1, 'ham': 0})
    email_df = email_df.dropna()
    
    X = email_df['text'].astype(str)
    y = email_df['label'].astype(int)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    tfidf = TfidfVectorizer(stop_words='english', max_features=1200)
    X_train_tfidf = tfidf.fit_transform(X_train)
    X_test_tfidf = tfidf.transform(X_test)
    
    tfidf_feature_names = tfidf.get_feature_names_out()
    X_train_tfidf = pd.DataFrame(X_train_tfidf.toarray(), columns=tfidf_feature_names)
    X_test_tfidf = pd.DataFrame(X_test_tfidf.toarray(), columns=tfidf_feature_names)

    lr = LogisticRegression(solver='liblinear', random_state=42, max_iter=300)
    rf = RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1)
    lgb_model = lgb.LGBMClassifier(n_estimators=120, random_state=42, verbose=-1, n_jobs=-1)

    lr.fit(X_train_tfidf, y_train)
    rf.fit(X_train_tfidf, y_train)
    lgb_model.fit(X_train_tfidf, y_train)

    print('\n  Individual Models:')
    evaluate_model(y_test, lr.predict(X_test_tfidf), 'Logistic Regression')
    evaluate_model(y_test, rf.predict(X_test_tfidf), 'Random Forest')
    evaluate_model(y_test, lgb_model.predict(X_test_tfidf), 'LightGBM')

    voting_clf = VotingClassifier(
        estimators=[
            ('lr', LogisticRegression(solver='liblinear', random_state=42, max_iter=300)),
            ('rf', RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1)),
            ('lgb', lgb.LGBMClassifier(n_estimators=120, random_state=42, verbose=-1, n_jobs=-1))
        ],
        voting='soft',
        n_jobs=-1
    )
    voting_clf.fit(X_train_tfidf, y_train)
    print('\n  Ensemble:')
    evaluate_model(y_test, voting_clf.predict(X_test_tfidf), 'Soft Voting Ensemble')

    full_tfidf_sparse = tfidf.fit_transform(X)
    full_tfidf = pd.DataFrame(full_tfidf_sparse.toarray(), columns=tfidf_feature_names)
    voting_clf_full = VotingClassifier(
        estimators=[
            ('lr', LogisticRegression(solver='liblinear', random_state=42, max_iter=300)),
            ('rf', RandomForestClassifier(n_estimators=120, random_state=42, n_jobs=-1)),
            ('lgb', lgb.LGBMClassifier(n_estimators=120, random_state=42, verbose=-1, n_jobs=-1))
        ],
        voting='soft',
        n_jobs=-1
    )
    voting_clf_full.fit(full_tfidf, y)

    joblib.dump(tfidf, MODEL_DIR / 'email_tfidf.joblib')
    joblib.dump(voting_clf_full, MODEL_DIR / 'email_model.joblib')
    print('✓ Email model saved')


def extract_url_features(url):
    """Extract simple features from URLs that indicate phishing."""
    features = {}
    
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
    features['has_https'] = 1 if url.startswith('https') else 0
    
    # Suspicious keywords
    suspicious = ['verify', 'confirm', 'login', 'update', 'account']
    features['suspicious_keywords'] = sum(1 for word in suspicious if word in url.lower())
    
    return features


def build_url_model():
    print('\n--- Building URL Model (Soft Voting Ensemble) ---')
    url_df = pd.read_csv(URL_DATA)
    url_df = url_df.rename(columns={'URL': 'url', 'Label': 'label'})
    url_df['label'] = url_df['label'].map({'bad': 1, 'good': 0})
    url_df = url_df.dropna()
    
    X = url_df['url'].astype(str)
    y = url_df['label'].astype(int)
    
    # Extract features instead of TF-IDF vectorization (much faster)
    print('  Extracting URL features...')
    features_list = [extract_url_features(url) for url in X]
    X_features = pd.DataFrame(features_list)
    
    X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.2, random_state=42, stratify=y)

    # Train ensemble directly on test/train split for evaluation
    voting_clf = VotingClassifier(
        estimators=[
            ('lr', LogisticRegression(solver='liblinear', random_state=42, max_iter=300, class_weight='balanced')),
            ('rf', RandomForestClassifier(n_estimators=60, random_state=42, n_jobs=-1, class_weight='balanced')),
            ('lgb', lgb.LGBMClassifier(n_estimators=60, random_state=42, verbose=-1, n_jobs=-1, is_unbalanced=True))
        ],
        voting='soft',
        weights=[1, 3, 3],
        n_jobs=-1
    )
    voting_clf.fit(X_train, y_train)
    print('\n  Ensemble (test set):')
    evaluate_model(y_test, voting_clf.predict(X_test), 'Soft Voting Ensemble')

    # Train final ensemble on full dataset
    voting_clf_full = VotingClassifier(
        estimators=[
            ('lr', LogisticRegression(solver='liblinear', random_state=42, max_iter=300, class_weight='balanced')),
            ('rf', RandomForestClassifier(n_estimators=60, random_state=42, n_jobs=-1, class_weight='balanced')),
            ('lgb', lgb.LGBMClassifier(n_estimators=60, random_state=42, verbose=-1, n_jobs=-1, is_unbalanced=True))
        ],
        voting='soft',
        weights=[1, 3, 3],
        n_jobs=-1
    )
    voting_clf_full.fit(X_features, y)

    joblib.dump(voting_clf_full, MODEL_DIR / 'url_model.joblib')
    print('✓ URL model saved')


def main():
    print('=' * 60)
    print('Training PhishGuard Models (Soft Voting Ensemble)')
    print('=' * 60)
    build_email_model()
    build_url_model()
    print('\n' + '=' * 60)
    print('✓ Training complete. Models saved in ml/models.')
    print('=' * 60)


if __name__ == '__main__':
    main()

