const express = require('express');
const cors = require('cors');
const path = require('path');
const fetch = require('node-fetch');
const { saveAnalysis, getAnalysisHistory, getAnalysisById } = require('./database');

const app = express();
app.use(cors());
app.use(express.json());

const ML_API_URL = process.env.ML_API_URL || 'http://localhost:5000/predict';

app.post('/api/predict', async (req, res) => {
  try {
    const { text, url } = req.body;
    if ((!text || !text.trim()) && (!url || !url.trim())) {
      return res.status(400).json({ error: 'Email text or URL is required for prediction.' });
    }

    const payload = {
      type: url ? 'url' : 'email',
      input: url ? url.trim() : text.trim(),
    };

    const response = await fetch(ML_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      return res.status(502).json({ error: 'ML API error', details: errorBody });
    }

    const mlResult = await response.json();

    // Save analysis to database
    try {
      const resultString = mlResult.isPhishing ? 'phishing' : 'safe';
      await saveAnalysis(payload.type, payload.input, resultString, mlResult.confidence, mlResult.isPhishing);
    } catch (dbError) {
      console.error('Database save error:', dbError);
      // Don't fail the request if database save fails
    }

    return res.json(mlResult);
  } catch (error) {
    console.error('Backend proxy error:', error);
    return res.status(500).json({ error: 'Backend error contacting ML API' });
  }
});

// Get analysis history
app.get('/api/history', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const history = await getAnalysisHistory(limit);
    return res.json(history);
  } catch (error) {
    console.error('History fetch error:', error);
    return res.status(500).json({ error: 'Failed to fetch analysis history' });
  }
});

// Get specific analysis by ID
app.get('/api/analysis/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const analysis = await getAnalysisById(id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    return res.json(analysis);
  } catch (error) {
    console.error('Analysis fetch error:', error);
    return res.status(500).json({ error: 'Failed to fetch analysis' });
  }
});

const buildPath = path.join(__dirname, '../frontend/build');
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(buildPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
  });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'PhishGuard backend is online', version: '1.0.0' });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`PhishGuard backend listening on http://localhost:${port}`);
});