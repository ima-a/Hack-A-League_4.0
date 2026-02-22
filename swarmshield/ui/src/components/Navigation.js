import React from 'react';
import { motion } from 'framer-motion';
import { FiAlertTriangle, FiShield, FiHome, FiBook } from 'react-icons/fi';
import '../styles/Navigation.css';

export default function Navigation({ currentPage, setCurrentPage, threatLevel }) {
  const getThreatColor = () => {
    if (threatLevel === 'critical') return '#ffffff';
    if (threatLevel === 'medium') return '#cccccc';
    return '#a0a0a0';
  };

  return (
    <nav className="navigation">
      <div className="nav-container">
        <div className="nav-brand">
          <motion.div
            animate={{ scale: [1, 1.05, 1] }}
            transition={{ duration: 0.5, repeat: threatLevel === 'critical' ? Infinity : 0 }}
            className="nav-logo"
            onClick={() => setCurrentPage('home')}
            role="button"
            tabIndex={0}
            style={{ cursor: 'pointer' }}
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
                      '0 0 10px rgba(255,255,255,0.5)',
                      '0 0 20px rgba(255,255,255,0.8)',
                      '0 0 10px rgba(255,255,255,0.5)',
                    ]
                  : `0 0 10px rgba(160,160,160,0.3)`,
            }}
            transition={{ duration: 1, repeat: threatLevel === 'critical' ? Infinity : 0 }}
            style={{ borderColor: getThreatColor() }}
          >
            <FiAlertTriangle size={16} color={getThreatColor()} />
            <span className="threat-level">{threatLevel.toUpperCase()}</span>
          </motion.div>
        </div>

        <div className="nav-right">
          <motion.button
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            className={`nav-button ${currentPage === 'home' ? 'active' : ''}`}
            onClick={() => setCurrentPage('home')}
          >
            <FiHome size={20} />
            <span>Home</span>
          </motion.button>
          
          <motion.button
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            className={`nav-button ${currentPage === 'documentation' ? 'active' : ''}`}
            onClick={() => setCurrentPage('documentation')}
          >
            <FiBook size={20} />
            <span>Documentation</span>
          </motion.button>
        </div>
      </div>
    </nav>
  );
}
