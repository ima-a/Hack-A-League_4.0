import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { FiChevronDown, FiChevronUp } from 'react-icons/fi';
import '../styles/AgentPanels.css';

const agentIcons = {
  scout: '🔭',
  analyzer: '🧬',
  responder: '⚡',
  evolver: '🔮',
};

export default function AgentPanels({ agents, selectedAgents }) {
  const [expandedAgent, setExpandedAgent] = useState(null);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
    },
  };

  return (
    <motion.div
      className="agent-panels"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      <h3 className="panels-title">🤖 Agent Insights & Analysis</h3>
      <div className="panels-grid">
        {Object.entries(agents).map(([key, agent], idx) => (
          <motion.div
            key={key}
            className={`agent-panel ${key}`}
            variants={itemVariants}
            layout
          >
            <motion.div
              className="agent-header"
              onClick={() =>
                setExpandedAgent(expandedAgent === key ? null : key)
              }
              whileHover={{ scale: 1.02 }}
            >
              <div className="agent-title">
                <span className="agent-icon">{agentIcons[key]}</span>
                <h4>{agent.name}</h4>
              </div>
              <div className="agent-status">
                <span
                  className="status-indicator"
                  style={{
                    backgroundColor:
                      agent.status === 'active' ? '#4caf50' : '#ff9800',
                  }}
                />
                {agent.status}
              </div>
              <motion.div
                animate={{ rotate: expandedAgent === key ? 180 : 0 }}
                transition={{ duration: 0.3 }}
              >
                {expandedAgent === key ? (
                  <FiChevronUp size={20} />
                ) : (
                  <FiChevronDown size={20} />
                )}
              </motion.div>
            </motion.div>

            <motion.div
              className="agent-content"
              initial={{ height: 0, opacity: 0 }}
              animate={{
                height: expandedAgent === key ? 'auto' : 0,
                opacity: expandedAgent === key ? 1 : 0,
              }}
              transition={{ duration: 0.3 }}
              style={{ overflow: 'hidden' }}
            >
              {/* Thinking Process */}
              <div className="agent-section">
                <h5>💭 Thinking Process</h5>
                <motion.p
                  animate={{ opacity: [1, 0.7, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  {agent.thinking}
                </motion.p>
              </div>

              {/* Key Metrics */}
              <div className="agent-metrics">
                {key === 'scout' && (
                  <>
                    <div className="metric">
                      <span className="metric-label">Detections</span>
                      <motion.span
                        className="metric-value"
                        animate={{ scale: [1, 1.1, 1] }}
                        transition={{ duration: 0.5 }}
                      >
                        {agent.detections}
                      </motion.span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Confidence</span>
                      <span className="metric-value">
                        {(agent.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </>
                )}
                {key === 'analyzer' && (
                  <>
                    <div className="metric">
                      <span className="metric-label">Correlations</span>
                      <motion.span
                        className="metric-value"
                        animate={{ scale: [1, 1.1, 1] }}
                        transition={{ duration: 0.5 }}
                      >
                        {agent.correlations}
                      </motion.span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Risk Score</span>
                      <span className="metric-value">
                        {(agent.riskScore * 100).toFixed(1)}%
                      </span>
                    </div>
                  </>
                )}
                {key === 'responder' && (
                  <>
                    <div className="metric">
                      <span className="metric-label">Actions Executed</span>
                      <motion.span
                        className="metric-value"
                        animate={{ scale: [1, 1.1, 1] }}
                        transition={{ duration: 0.5 }}
                      >
                        {agent.actionsExecuted}
                      </motion.span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">IPs Blocked</span>
                      <span className="metric-value">{agent.blocked}</span>
                    </div>
                  </>
                )}
                {key === 'evolver' && (
                  <>
                    <div className="metric">
                      <span className="metric-label">Generation</span>
                      <motion.span
                        className="metric-value"
                        animate={{ scale: [1, 1.1, 1] }}
                        transition={{ duration: 0.5 }}
                      >
                        {agent.generation}
                      </motion.span>
                    </div>
                    <div className="metric">
                      <span className="metric-label">Fitness Score</span>
                      <span className="metric-value">
                        {(agent.fitness * 100).toFixed(1)}%
                      </span>
                    </div>
                  </>
                )}
              </div>

              {/* Insights */}
              <div className="agent-section">
                <h5>💡 Current Insights</h5>
                <ul className="insights-list">
                  {agent.insights.map((insight, i) => (
                    <motion.li
                      key={i}
                      initial={{ x: -10, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      transition={{ delay: i * 0.1 }}
                    >
                      <span className="insight-icon">→</span>
                      {insight}
                    </motion.li>
                  ))}
                </ul>
              </div>

              {/* Communication Status */}
              {key === 'scout' && (
                <div className="communication-status">
                  <span className="comm-arrow">→</span>
                  <span>Connected to Analyzer</span>
                </div>
              )}
              {key === 'analyzer' && (
                <div className="communication-status">
                  <span className="comm-arrow">→</span>
                  <span>Connected to Responder</span>
                </div>
              )}
              {key === 'responder' && (
                <div className="communication-status">
                  <span className="comm-arrow">→</span>
                  <span>Connected to Evolver</span>
                </div>
              )}
              {key === 'evolver' && (
                <div className="communication-status">
                  <span className="comm-arrow">→</span>
                  <span>Connected to Scout</span>
                </div>
              )}
            </motion.div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
