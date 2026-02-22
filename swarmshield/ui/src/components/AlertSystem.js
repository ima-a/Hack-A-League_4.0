import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { FiAlertTriangle, FiCheckCircle } from 'react-icons/fi';
import '../styles/AlertSystem.css';

export default function AlertSystem({ threatLevel }) {
  const getAlertColor = () => {
    if (threatLevel === 'critical') return '#ffffff';
    if (threatLevel === 'medium') return '#cccccc';
    return '#a0a0a0';
  };

  const getAlertMessage = () => {
    if (threatLevel === 'critical') return 'CRITICAL THREAT - Multiple attacks detected';
    if (threatLevel === 'medium') return 'MEDIUM ALERT - Suspicious activity detected';
    return 'SECURE - All systems normal';
  };

  return (
    <motion.div
      className="alert-system"
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ delay: 0.15 }}
    >
      <div className="alert-container">
        <motion.div
          className="alert-button"
          animate={
            threatLevel === 'critical'
              ? {
                  boxShadow: [
                    '0 0 10px rgba(255,255,255,0.5)',
                    '0 0 30px rgba(255,255,255,0.8)',
                    '0 0 10px rgba(255,255,255,0.5)',
                  ],
                }
              : {}
          }
          transition={{ duration: 0.8, repeat: threatLevel === 'critical' ? Infinity : 0 }}
          style={{
            backgroundColor: getAlertColor(),
            border: `2px solid ${getAlertColor()}`,
          }}
        >
          {threatLevel === 'critical' ? (
            <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity }}>
              <FiAlertTriangle size={32} />
            </motion.div>
          ) : (
            <FiCheckCircle size={32} />
          )}
        </motion.div>

        <div className="alert-content">
          <h3>{getAlertMessage()}</h3>
          <div className="alert-stats">
            <div className="stat">
              <span className="stat-label">Threats Detected</span>
              <span className="stat-value">{Math.floor(Math.random() * 25)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Attack Vectors</span>
              <span className="stat-value">{Math.floor(Math.random() * 8)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Response Rate</span>
              <span className="stat-value">98%</span>
            </div>
          </div>
        </div>

        <motion.div className="alert-pulse" />
      </div>
    </motion.div>
  );
}
