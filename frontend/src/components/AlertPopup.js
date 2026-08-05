import React from 'react';

const styles = {
  base: {
    position: 'fixed',
    right: '1.5rem',
    bottom: '1.5rem',
    zIndex: 999,
    minWidth: '280px',
    borderRadius: '16px',
    padding: '1rem 1.2rem',
    boxShadow: '0 20px 45px rgba(0, 0, 0, 0.22)',
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    color: '#fff',
  },
  success: {
    background: 'linear-gradient(135deg, #16a34a 0%, #22c55e 100%)',
  },
  danger: {
    background: 'linear-gradient(135deg, #dc2626 0%, #f97316 100%)',
  },
  warning: {
    background: 'linear-gradient(135deg, #f59e0b 0%, #facc15 100%)',
    color: '#0f172a',
  },
  info: {
    background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
  },
};

function AlertPopup({ message, type = 'info' }) {
  return (
    <div style={{ ...styles.base, ...styles[type] }}>
      <span style={{ fontSize: '1rem', fontWeight: 700 }}>{message}</span>
    </div>
  );
}

export default AlertPopup;
