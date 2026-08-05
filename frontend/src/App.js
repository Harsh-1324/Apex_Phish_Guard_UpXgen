import React, { useState, useEffect } from 'react';
import AlertPopup from './components/AlertPopup';
import ResultPanel from './components/ResultPanel';
import HistoryCard from './components/HistoryCard';
import { predict, getHistory } from './utils/api';
import './App.css';

const suspiciousTerms = [
  'verify', 'suspend', 'password', 'urgent', 'click here', 'account',
  'security', 'login', 'confirm', 'update', 'bank', 'credit card',
  'reward', 'limited', 'action required', 'incident', 'authenticate',
  'invoice', 'verify your', 'unusual activity'
];

const examples = {
  email: `Dear customer,\n\nYour account has been temporarily suspended due to unusual activity. Please verify your account immediately by clicking the link below:\n\nhttps://secure-bank.example.com/verify\n\nThank you for your prompt action.`,
  url: 'https://secure-login.example.com/account/confirm?token=abc123',
};

const escapeHtml = (text) =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const highlightText = (content) => {
  const safe = escapeHtml(content);
  const regex = new RegExp(`\\b(${suspiciousTerms.join('|')})\\b`, 'gi');
  return safe.replace(regex, '<span class="highlight">$1</span>');
};

function App() {
  const [mode, setMode] = useState('email');
  const [textInput, setTextInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [result, setResult] = useState(null);
  const [alert, setAlert] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  // Load history on component mount
  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      const historyData = await getHistory(3);
      setHistory(historyData);
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  };

  const showAlert = (message, type = 'info') => {
    setAlert({ message, type });
    setTimeout(() => setAlert(null), 6000);
  };

  const handleAnalyze = async () => {
    const payload = mode === 'email' ? { text: textInput } : { url: urlInput };

    if (!payload.text && !payload.url) {
      return showAlert('Enter email content or URL before scanning.', 'warning');
    }

    if (mode === 'url' && !payload.url.startsWith('http')) {
      return showAlert('Include http:// or https:// for URL checks.', 'warning');
    }

    setLoading(true);
    try {
      const prediction = await predict(payload);
      setResult(prediction);

      // Reload history after analysis (since it's saved to database)
      await loadHistory();

      if (prediction.isPhishing) {
        showAlert('Phishing detected — stay alert and do not click suspicious links.', 'danger');
      } else {
        showAlert('Safe content detected. Keep your guard up!', 'success');
      }
    } catch (error) {
      console.error(error);
      showAlert('Unable to connect to the backend. Check servers and try again.', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const handleUseExample = () => {
    if (mode === 'email') {
      setTextInput(examples.email);
    } else {
      setUrlInput(examples.url);
    }
  };

  const clearForm = () => {
    setTextInput('');
    setUrlInput('');
    setResult(null);
  };

  return (
    <div className="app-shell">
      <div className="hero-panel">
        <div className="hero-copy">
          <div className="eyebrow">PhishGuard</div>
          <h1>Stop phishing attacks before they hit your inbox.</h1>
          <p>
            Real-time phishing analysis with confidence scoring, suspicious keyword
            highlighting, and instant explanation for every prediction.
          </p>
          <div className="hero-actions">
            <button className="button button-primary" onClick={handleAnalyze} disabled={loading}>
              {loading ? 'Analyzing...' : 'Run Scan'}
            </button>
            <button className="button button-outline" onClick={handleUseExample}>
              Load Example
            </button>
          </div>
          <div className="pill-row">
            <span>AI + TF-IDF</span>
            <span>Random Forest URL checks</span>
            <span>Confidence & alerts</span>
          </div>
        </div>
        <div className="hero-card">
          <div className="hero-card-top">
            <div>
              <span className="tiny-label">Attack type</span>
              <h2>{mode === 'email' ? 'Email Phishing Scan' : 'URL Threat Scan'}</h2>
            </div>
            <div className="toggle-pill">
              <button className={mode === 'email' ? 'active' : ''} onClick={() => setMode('email')}>
                Email
              </button>
              <button className={mode === 'url' ? 'active' : ''} onClick={() => setMode('url')}>
                URL
              </button>
            </div>
          </div>
          <label className="input-label">{mode === 'email' ? 'Email content' : 'URL to analyze'}</label>
          {mode === 'email' ? (
            <textarea
              className="input-field"
              rows="9"
              placeholder="Paste phishing email text here"
              value={textInput}
              onChange={(event) => setTextInput(event.target.value)}
            />
          ) : (
            <input
              className="input-field"
              placeholder="https://example.com/login"
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
            />
          )}
          <div className="input-footer">
            <span className="hint-text">Suspicious phrases are highlighted in the result panel.</span>
            <button className="link-button" type="button" onClick={clearForm}>
              Clear input
            </button>
          </div>
        </div>
      </div>

      <div className="dashboard-row">
        <div className="dashboard-column">
          <ResultPanel
            result={result}
            mode={mode}
            highlightText={highlightText}
          />
          <div className="explain-card">
            <h3>Why PhishGuard trusts this result</h3>
            <p>
              Every prediction is backed by model confidence, feature analysis, and
              a threat explanation so you can act with clarity.
            </p>
            <ul>
              <li>Confidence score from the ML model</li>
              <li>Keyword and URL pattern inspection</li>
              <li>Live alert system for phishing detections</li>
            </ul>
          </div>
        </div>

        <div className="dashboard-column right-column">
          <div className="history-card">
            <div className="history-card-header">
              <div>
                <h3>Scan history</h3>
                <p>Most recent 3 analysis sessions</p>
              </div>
            </div>
            {history.length === 0 ? (
              <p className="muted-text">No scans yet. Run a check to see recent results here.</p>
            ) : (
              history.map((item) => <HistoryCard key={item.id} item={item} />)
            )}
          </div>
          <div className="insight-box">
            <h4>Security insight</h4>
            <p>
              Phishing attackers often use urgency, familiar brand names, and hidden redirects.
              Watch for any anomalies before entering credentials.
            </p>
          </div>
        </div>
      </div>

      {alert && <AlertPopup message={alert.message} type={alert.type} />}
    </div>
  );
}

export default App;
