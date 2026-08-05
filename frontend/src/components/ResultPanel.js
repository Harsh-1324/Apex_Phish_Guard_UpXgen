import React from 'react';

function ResultPanel({ result, mode, highlightText }) {
  if (!result) {
    return (
      <div className="explain-card">
        <h3>Prediction summary</h3>
        <p className="muted-text">Run a scan to see score, explanations, and suspicious pattern highlights.</p>
      </div>
    );
  }

  const { isPhishing, confidence, reasons, details, analysisDetails } = result;
  const statusLabel = isPhishing ? 'Phishing detected' : 'No issue found';
  const statusClass = isPhishing ? 'result-pill danger' : 'result-pill safe';

  return (
    <div className="explain-card">
      <div className="result-title-row">
        <div>
          <span className={statusClass}>{statusLabel}</span>
          <h3>{mode === 'email' ? 'Email security report' : 'URL threat report'}</h3>
        </div>
        <div className="confidence-chip">
          <strong>{confidence}%</strong>
          <span>confidence</span>
        </div>
      </div>

      <div className="confidence-bar">
        <div className="confidence-fill" style={{ width: `${confidence}%` }} />
      </div>

      <div className="prediction-copy">
        <p>{isPhishing ? 'This sample contains multiple indicators associated with phishing attacks.' : 'This scan appears safe, but always review any unexpected messages carefully.'}</p>
      </div>

      {isPhishing && (
        <div className="analysis-warning-banner">
          <span className="warning-icon">⚠️</span>
          <span>Do not click any links, download attachments, or share personal information.</span>
        </div>
      )}

      {analysisDetails && analysisDetails.length > 0 && (
        <div className="analysis-details-block">
          <h4>Analysis Details</h4>
          <div className="analysis-details-list">
            {analysisDetails.map((detail, index) => (
              <div key={index} className="analysis-detail-item">
                <span className="detail-icon">⚠️</span>
                <span className="detail-text">{detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="prediction-block">
        <h4>Key reasons</h4>
        <ul>
          {reasons.map((reason, index) => (
            <li key={index}>{reason}</li>
          ))}
        </ul>
      </div>

      <div className="prediction-block">
        <h4>Highlighted suspicious content</h4>
        <div
          className="highlighted-preview"
          dangerouslySetInnerHTML={{ __html: highlightText(mode === 'email' ? result.input : result.input || '') }}
        />
      </div>

      {details && (
        <div className="prediction-block">
          <h4>Model details</h4>
          <p>{details}</p>
        </div>
      )}
    </div>
  );
}

export default ResultPanel;
