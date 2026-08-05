import React from 'react';

function HistoryCard({ item }) {
  const snippet = item.input ? item.input.slice(0, 90) + (item.input.length > 90 ? '...' : '') : 'No input available';
  const mode = item.type || item.mode || 'unknown';
  
  // Parse timestamp and display local time
  let timeDisplay = 'unknown';
  if (item.timestamp) {
    // SQLite CURRENT_TIMESTAMP is UTC, convert it properly
    // Format: "YYYY-MM-DD HH:MM:SS" -> convert to ISO with Z for UTC
    const isoString = String(item.timestamp).replace(' ', 'T') + 'Z';
    const date = new Date(isoString);
    timeDisplay = date.toLocaleString([], { 
      month: 'short', 
      day: 'numeric', 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: true 
    });
  }

  return (
    <div className="history-item">
      <div className="history-item-top">
        <span className={item.isPhishing ? 'history-badge danger' : 'history-badge safe'}>
          {item.isPhishing ? 'Threat' : 'Safe'}
        </span>
        <span className="history-score">{Math.round(item.confidence)}%</span>
      </div>
      <p className="history-snippet">{snippet}</p>
      <div className="history-meta">
        <span>{mode.toUpperCase()}</span>
        <span>{timeDisplay}</span>
      </div>
    </div>
  );
}

export default HistoryCard;
