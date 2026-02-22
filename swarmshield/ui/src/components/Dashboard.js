import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import AlertSystem from './AlertSystem';
import NetworkLogs from './NetworkLogs';
import AgentPanels from './AgentPanels';
import CommunicationToggle from './CommunicationToggle';
import AgentDocumentation from './AgentDocumentation';
import '../styles/Dashboard.css';

export default function Dashboard({ threatLevel, setThreatLevel }) {
  const [selectedAgents, setSelectedAgents] = useState({
    scoutToAnalyzer: true,
    analyzerToResponder: true,
    responderToEvolver: true,
    evolverToScout: true,
    allAgents: false,
  });

  const [agents, setAgents] = useState({
    scout: {
      name: 'Scout',
      status: 'active',
      thinking: 'Monitoring network traffic for anomalies...',
      detections: 12,
      confidence: 0.92,
      insights: ['DDoS pattern detected', 'Port scan activity', 'Unusual data exfiltration'],
    },
    analyzer: {
      name: 'Analyzer',
      status: 'active',
      thinking: 'Correlating threat patterns across network...',
      correlations: 8,
      riskScore: 0.73,
      insights: ['Attack graph built', 'Lateral movement risk: HIGH', 'Coordinated attack detected'],
    },
    responder: {
      name: 'Responder',
      status: 'active',
      thinking: 'Executing defensive actions...',
      actionsExecuted: 23,
      blocked: 5,
      insights: ['5 IPs blocked', 'Honeypot engaged', 'Traffic redirected'],
    },
    evolver: {
      name: 'Evolver (Mahoraga)',
      status: 'active',
      thinking: 'Adapting to new attack patterns...',
      generation: 42,
      fitness: 0.88,
      insights: ['Thresholds optimized', 'Adaptation rating: 9.2/10', 'Blind spots identified'],
    },
  });

  const [showDocumentation, setShowDocumentation] = useState(false);

  // Simulate agent activity
  useEffect(() => {
    const interval = setInterval(() => {
      setAgents((prev) => ({
        ...prev,
        scout: {
          ...prev.scout,
          detections: Math.floor(Math.random() * 20),
          confidence: 0.8 + Math.random() * 0.2,
        },
        analyzer: {
          ...prev.analyzer,
          correlations: Math.floor(Math.random() * 15),
          riskScore: 0.5 + Math.random() * 0.5,
        },
        responder: {
          ...prev.responder,
          actionsExecuted: Math.floor(Math.random() * 30),
          blocked: Math.floor(Math.random() * 10),
        },
        evolver: {
          ...prev.evolver,
          generation: prev.evolver.generation + 1,
          fitness: 0.75 + Math.random() * 0.25,
        },
      }));
    }, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      className="dashboard"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <div className="dashboard-grid">
        {/* Header Section */}
        <motion.div
          className="dashboard-header"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <div className="header-content">
            <h2>Autonomous Threat Defense Network</h2>
            <p>Real-time multi-agent security orchestration</p>
          </div>
        </motion.div>

        {/* Alert System */}
        <AlertSystem threatLevel={threatLevel} />

        {/* Communication Control */}
        <CommunicationToggle selectedAgents={selectedAgents} setSelectedAgents={setSelectedAgents} />

        {/* Network Logs */}
        <NetworkLogs />

        {/* Agent Panels */}
        <AgentPanels agents={agents} selectedAgents={selectedAgents} />

        {/* Documentation Toggle */}
        <motion.div
          className="doc-toggle"
          whileHover={{ scale: 1.05 }}
          onClick={() => setShowDocumentation(!showDocumentation)}
        >
          <button className="doc-button">
            {showDocumentation ? '📖 Hide Documentation' : '📖 View Agent Documentation'}
          </button>
        </motion.div>

        {/* Agent Documentation */}
        {showDocumentation && <AgentDocumentation />}
      </div>
    </motion.div>
  );
}
