const API_URL = 'http://localhost:3001/api/predict';

export async function predict(payload) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Prediction request failed');
  }

  return response.json();
}

export async function getHistory(limit = 3) {
  const response = await fetch(`http://localhost:3001/api/history?limit=${limit}`);

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'History fetch failed');
  }

  return response.json();
}

export async function getAnalysisById(id) {
  const response = await fetch(`http://localhost:3001/api/analysis/${id}`);

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Analysis fetch failed');
  }

  return response.json();
}
