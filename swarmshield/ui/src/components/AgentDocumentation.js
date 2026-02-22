import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FiChevronDown, FiChevronUp } from 'react-icons/fi';
import '../styles/AgentDocumentation.css';

export default function AgentDocumentation() {
  const [expandedDoc, setExpandedDoc] = useState('scout');

  const agents = [
    {
      id: 'scout',
      name: 'Scout 🔭',
      fullName: 'Network Threat Detection Agent',
      icon: '🔭',
      color: '#00bcd4',
      description:
        'The first line of defense - scans network traffic in real-time for anomalous patterns.',
      responsibilities: [
        'Real-time packet analysis and classification',
        'DDoS detection using statistical anomaly detection',
        'Port scanning detection with entropy analysis',
        'Data exfiltration identification',
        'Confidence-based threat reporting',
        'Sliding window packet analysis (10-second windows)',
      ],
      detectionMethods: [
        'Monte Carlo simulation-based threat classification',
        'Shannon entropy calculation for port distribution analysis',
        'Statistical anomaly detection on traffic patterns',
        'LLM-enhanced threat classification',
        'Rolling inference predictions',
      ],
      keyMetrics: ['Threat Confidence', 'Detection Rate', 'False Positive Rate'],
      threatTypes: ['DDoS Attacks', 'Port Scans', 'Data Exfiltration', 'Anomalous Patterns'],
    },
    {
      id: 'analyzer',
      name: 'Analyzer 🧬',
      fullName: 'Threat Correlation & Attack Graph Engine',
      icon: '🧬',
      color: '#9c27b0',
      description:
        'Correlates threats detected by Scout and builds attack graphs to identify coordinated assaults.',
      responsibilities: [
        'Threat correlation across multiple sources',
        'Attack graph construction and analysis',
        'Lateral movement risk assessment',
        'Propagation probability simulation',
        'Risk scoring for network nodes',
        'Recommended action generation',
      ],
      analysisTypes: [
        'Coordinated attack detection',
        'Independent threat evaluation',
        'Propagation simulation with Monte Carlo',
        'Lateral movement pattern analysis',
        'Attack vector mapping',
      ],
      keyMetrics: ['Risk Score', 'Confidence Level', 'Spread Metric', 'Node Count'],
      outputs: [
        'Threat correlations',
        'Attack graph visualization',
        'Risk assessments',
        'Recommended defensive actions',
      ],
    },
    {
      id: 'responder',
      name: 'Responder ⚡',
      fullName: 'Active Defense & Response Executor',
      icon: '⚡',
      color: '#ff5722',
      description:
        'Takes decisive action against identified threats - blocks malicious IPs, redirects traffic, and engages honeypots.',
      responsibilities: [
        'IP blocking via iptables rules',
        'Traffic redirection mechanisms',
        'Honeypot engagement',
        'Action logging and reporting',
        'Auto-unblock scheduling',
        'Real-time threat response coordination',
      ],
      actionTypes: [
        'Block IP addresses and subnets',
        'Rate limiting on suspicious traffic',
        'Honeypot redirects',
        'Traffic isolation',
        'Service shutdown/restart',
      ],
      keyMetrics: ['Blocked IPs', 'Actions Executed', 'Response Time', 'Threat Mitigation %'],
      capabilities: [
        'Immediate threat neutralization',
        'Multi-vector attack mitigation',
        'Graceful degradation handling',
        'Autonomous decision-making with human oversight',
      ],
    },
    {
      id: 'evolver',
      name: 'Evolver (Mahoraga) 🔮',
      fullName: 'Adaptive Defense Strategy Evolution',
      icon: '🔮',
      color: '#f44336',
      description:
        'Named after the Divine General from Jujutsu Kaisen - evolves detection thresholds using genetic algorithms to adapt to new attack patterns.',
      responsibilities: [
        'Genetic algorithm-based threshold optimization',
        'Defense strategy evolution from real outcomes',
        'False positive/negative minimization',
        'Gene fitness evaluation',
        'Threshold recommendation generation',
      ],
      evolutionProcess: [
        'Population initialization with random thresholds',
        'Fitness evaluation based on TP/TN/FP/FN',
        'Selection of top performers',
        'Crossover and mutation operations',
        'LLM advisory for strategy assessment',
      ],
      evolvedParameters: [
        'DDoS packets/sec threshold',
        'DDoS SYN packet threshold',
        'Port scan unique IP threshold',
        'Port scan entropy threshold',
        'Data exfiltration bytes/sec threshold',
        'Overall confidence threshold',
      ],
      adaptation: 'Continuously learns from attack outcomes to improve detection accuracy',
      mahoragaRef: 'Adapts to all techniques, like the legendary Divine General Mahoraga',
    },
  ];

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
      className="agent-documentation"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      <div className="doc-header">
        <h2>📚 Agent Documentation & Architecture</h2>
        <p>Complete breakdown of each autonomous agent's capabilities and workflow</p>
      </div>

      <div className="doc-tabs">
        {agents.map((agent) => (
          <motion.button
            key={agent.id}
            className={`doc-tab ${expandedDoc === agent.id ? 'active' : ''}`}
            onClick={() => setExpandedDoc(agent.id)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            style={{
              borderColor: expandedDoc === agent.id ? agent.color : 'transparent',
            }}
          >
            <span className="tab-icon">{agent.icon}</span>
            {agent.name.split(' ')[0]}
          </motion.button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {agents.map((agent) => (
          expandedDoc === agent.id && (
            <motion.div
              key={agent.id}
              className="doc-content"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              style={{ borderTopColor: agent.color }}
            >
              <div className="agent-header-doc">
                <div className="agent-title-doc">
                  <span className="agent-icon-large">{agent.icon}</span>
                  <div>
                    <h3>{agent.fullName}</h3>
                    <p className="agent-desc">{agent.description}</p>
                  </div>
                </div>
              </div>

              <div className="doc-grid">
                {/* Main Responsibilities */}
                <div className="doc-section">
                  <h4>🎯 Primary Responsibilities</h4>
                  <ul className="doc-list">
                    {agent.responsibilities.map((resp, idx) => (
                      <motion.li
                        key={idx}
                        initial={{ x: -10, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                      >
                        <span className="list-dot" style={{ backgroundColor: agent.color }} />
                        {resp}
                      </motion.li>
                    ))}
                  </ul>
                </div>

                {/* Specific Methods/Types */}
                <div className="doc-section">
                  <h4>
                    {agent.id === 'scout'
                      ? '🔬 Detection Methods'
                      : agent.id === 'analyzer'
                      ? '📊 Analysis Types'
                      : agent.id === 'responder'
                      ? '⚙️ Action Types'
                      : '🧬 Evolution Process'}
                  </h4>
                  <ul className="doc-list">
                    {(agent.detectionMethods ||
                      agent.analysisTypes ||
                      agent.actionTypes ||
                      agent.evolutionProcess
                    ).map((method, idx) => (
                      <motion.li
                        key={idx}
                        initial={{ x: -10, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                      >
                        <span className="list-dot" style={{ backgroundColor: agent.color }} />
                        {method}
                      </motion.li>
                    ))}
                  </ul>
                </div>

                {/* Key Metrics or Parameters */}
                <div className="doc-section">
                  <h4>
                    {agent.id === 'evolver'
                      ? '⚙️ Evolved Parameters'
                      : agent.id === 'responder'
                      ? '📈 Key Metrics'
                      : '📊 Key Metrics'}
                  </h4>
                  <ul className="doc-list">
                    {(agent.evolvedParameters ||
                      agent.keyMetrics ||
                      agent.outputs ||
                      agent.capabilities
                    ).map((metric, idx) => (
                      <motion.li
                        key={idx}
                        initial={{ x: -10, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                      >
                        <span className="list-dot" style={{ backgroundColor: agent.color }} />
                        {metric}
                      </motion.li>
                    ))}
                  </ul>
                </div>

                {/* Special Info for Evolver */}
                {agent.id === 'evolver' && (
                  <div className="doc-section special-section">
                    <h4>🎬 Mahoraga Reference</h4>
                    <div className="special-content">
                      <p>{agent.mahoragaRef}</p>
                      <motion.div
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: 0.3 }}
                      >
                        <div
                          className="tenor-gif-embed"
                          data-postid="13326845355987467400"
                          data-share-method="host"
                          data-aspect-ratio="1.76596"
                          data-width="100%"
                        />
                        <script
                          type="text/javascript"
                          async
                          src="https://media.tenor.com/js/tenor.js"
                        />
                      </motion.div>
                      <p className="adaptation-note">{agent.adaptation}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Workflow Visualization */}
              <div className="workflow-section">
                <h4>🔄 Information Flow</h4>
                <div className="workflow-flow">
                  {agent.id === 'scout' && <div>Scout → Analyzer (Threat classification)</div>}
                  {agent.id === 'analyzer' && <div>Analyzer → Responder (Risk assessment & actions)</div>}
                  {agent.id === 'responder' && <div>Responder → Evolver (Defense outcome data)</div>}
                  {agent.id === 'evolver' && <div>Evolver → Scout (Optimized thresholds)</div>}
                </div>
              </div>
            </motion.div>
          )
        ))}
      </AnimatePresence>
    </motion.div>
  );
}
