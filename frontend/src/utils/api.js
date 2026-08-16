const API_URL = 'https://phish-guard-backend-dv8z.onrender.com/api';

// Auth functions
export async function signup(email, password) {
  const response = await fetch(`${API_URL}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Signup failed');
  }

  return response.json();
}

export async function login(email, password) {
  const response = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Login failed');
  }

  return response.json();
}

export async function getCurrentUser(token) {
  const response = await fetch(`${API_URL}/auth/me`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });

  if (!response.ok) {
    throw new Error('Failed to get current user');
  }

  return response.json();
}

// Predict function
export async function predict(payload, token) {
  const response = await fetch(`${API_URL}/predict`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Prediction request failed');
  }

  return response.json();
}

// History function
export async function getHistory(limit = 3, token) {
  const response = await fetch(`${API_URL}/history?limit=${limit}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'History fetch failed');
  }

  return response.json();
}

// Get analysis by ID
export async function getAnalysisById(id, token) {
  const response = await fetch(`${API_URL}/analysis/${id}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || 'Analysis fetch failed');
  }

  return response.json();
}
