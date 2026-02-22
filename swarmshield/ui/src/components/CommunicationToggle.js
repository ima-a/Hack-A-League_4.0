import React from 'react';
import { motion } from 'framer-motion';
import '../styles/CommunicationToggle.css';

export default function CommunicationToggle({ selectedAgents, setSelectedAgents }) {
  const toggleConnection = (key) => {
    setSelectedAgents((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const connections = [
    {
      key: 'scoutToAnalyzer',
      label: 'Scout → Analyzer',
      description: 'Threat detection flow',
      icon: '🔭 → 🧬',
    },
    {
      key: 'analyzerToResponder',
      label: 'Analyzer → Responder',
      description: 'Action recommendation',
      icon: '🧬 → ⚡',
    },
    {
      key: 'responderToEvolver',
      label: 'Responder → Evolver',
      description: 'Defense feedback',
      icon: '⚡ → 🔮',
    },
    {
      key: 'evolverToScout',
      label: 'Evolver → Scout',
      description: 'Threshold evolution',
      icon: '🔮 → 🔭',
    },
    {
      key: 'allAgents',
      label: 'All Agents Synchronized',
      description: 'Multi-agent consensus mode',
      icon: '🔄',
    },
  ];

  return (
    <motion.div
      className="communication-toggle"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.25 }}
    >
      <div className="toggle-header">
        <h3>🔗 Agent Communication Control</h3>
        <p>Enable/disable connections between agents</p>
      </div>

      <div className="connections-grid">
        {connections.map((connection) => (
          <motion.div
            key={connection.key}
            className={`connection-card ${
              selectedAgents[connection.key] ? 'active' : 'inactive'
            }`}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => toggleConnection(connection.key)}
          >
            <div className="connection-icon">{connection.icon}</div>

            <div className="connection-content">
              <h4>{connection.label}</h4>
              <p>{connection.description}</p>
            </div>

            <motion.div
              className="toggle-switch"
              animate={{
                backgroundColor: selectedAgents[connection.key]
                  ? '#00ff41'
                  : 'rgba(0, 50, 25, 0.3)',
              }}
            >
              <motion.div
                className="toggle-dot"
                animate={{
                  x: selectedAgents[connection.key] ? 20 : 0,
                }}
                transition={{ duration: 0.2 }}
              >
                {selectedAgents[connection.key] ? '✓' : '✕'}
              </motion.div>
            </motion.div>

            {selectedAgents[connection.key] && (
              <motion.div
                className="connection-pulse"
                animate={{
                  width: ['0%', '100%', '0%'],
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }}
              />
            )}
          </motion.div>
        ))}
      </div>

      <div className="communication-info">
        <div className="info-box enabled">
          <span className="info-label">Active Connections:</span>
          <span className="info-value">
            {Object.values(selectedAgents).filter(Boolean).length}
          </span>
        </div>
        <div className="info-box status">
          <span className="info-label">Network Status:</span>
          <span className="info-value healthy">HEALTHY</span>
        </div>
      </div>
    </motion.div>
  );
}
