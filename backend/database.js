const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '../phishguard.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening SQLite database:', err);
  } else {
    console.log(`Connected to SQLite database at ${dbPath}`);
  }
});

async function initDatabase() {
  const createTable = `
    CREATE TABLE IF NOT EXISTS analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      input TEXT NOT NULL,
      isPhishing INTEGER NOT NULL,
      result TEXT NOT NULL,
      confidence REAL NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;

  return new Promise((resolve, reject) => {
    db.run(createTable, (err) => {
      if (err) {
        console.error('Error creating SQLite table:', err);
        reject(err);
      } else {
        console.log('SQLite database initialized successfully.');
        resolve();
      }
    });
  });
}

initDatabase().catch(console.error);

async function saveAnalysis(type, input, result, confidence, isPhishing) {
  const query = `INSERT INTO analyses (type, input, isPhishing, result, confidence) VALUES (?, ?, ?, ?, ?)`;
  const values = [type, input, isPhishing ? 1 : 0, result, confidence];

  return new Promise((resolve, reject) => {
    db.run(query, values, function (err) {
      if (err) {
        console.error('Error saving analysis:', err);
        reject(err);
      } else {
        resolve({ id: this.lastID });
      }
    });
  });
}

async function getAnalysisHistory(limit = 50) {
  const query = `SELECT id, type, input, isPhishing, result, confidence, timestamp FROM analyses ORDER BY timestamp DESC LIMIT ?`;

  return new Promise((resolve, reject) => {
    db.all(query, [limit], (err, rows) => {
      if (err) {
        console.error('Error fetching history:', err);
        reject(err);
      } else {
        const results = rows.map((row) => ({
          ...row,
          isPhishing: Boolean(row.isPhishing),
        }));
        resolve(results);
      }
    });
  });
}

async function getAnalysisById(id) {
  const query = `SELECT id, type, input, isPhishing, result, confidence, timestamp FROM analyses WHERE id = ?`;

  return new Promise((resolve, reject) => {
    db.get(query, [id], (err, row) => {
      if (err) {
        console.error('Error fetching analysis:', err);
        reject(err);
      } else if (!row) {
        resolve(null);
      } else {
        resolve({
          ...row,
          isPhishing: Boolean(row.isPhishing),
        });
      }
    });
  });
}

process.on('exit', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed.');
    }
  });
});

module.exports = {
  saveAnalysis,
  getAnalysisHistory,
  getAnalysisById,
};