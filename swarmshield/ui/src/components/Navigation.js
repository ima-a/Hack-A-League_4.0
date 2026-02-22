import React from 'react';
import { motion } from 'framer-motion';
import { FiAlertTriangle, FiShield, FiGithub } from 'react-icons/fi';
import '../styles/Navigation.css';

export default function Navigation({ activeView, setActiveView, threatLevel }) {
  const getThreatColor = () => {
    if (threatLevel === 'critical') return '#ff1744';
    if (threatLevel === 'medium') return '#ff9800';
    return '#4caf50';
  };

  return (
    <nav className="navigation">
      <div className="nav-container">
        <div className="nav-brand">
          <motion.div
            animate={{ scale: [1, 1.05, 1] }}
            transition={{ duration: 0.5, repeat: threatLevel === 'critical' ? Infinity : 0 }}
            className="nav-logo"
          >
            <FiShield size={28} />
            <h1>SwarmShield</h1>
          </motion.div>
        </div>

        <div className="nav-center">
          <motion.div
            className="threat-indicator"
            animate={{
              boxShadow:
                threatLevel === 'critical'
                  ? [
                      '0 0 10px rgba(255,23,68,0.5)',
                      '0 0 20px rgba(255,23,68,0.8)',
                      '0 0 10px rgba(255,23,68,0.5)',
                    ]
                  : `0 0 10px rgba(76,175,80,0.3)`,
            }}
            transition={{ duration: 1, repeat: threatLevel === 'critical' ? Infinity : 0 }}
            style={{ borderColor: getThreatColor() }}
          >
            <FiAlertTriangle size={16} color={getThreatColor()} />
            <span className="threat-level">{threatLevel.toUpperCase()}</span>
          </motion.div>
        </div>

        <div className="nav-right">
          <motion.a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            className="nav-link"
          >
            <FiGithub size={24} />
          </motion.a>
        </div>
      </div>
    </nav>
  );
}
