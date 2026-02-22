import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import NetworkLogs from '../components/NetworkLogs';
import CommunicationToggle from '../components/CommunicationToggle';
import '../styles/HomePage.css';

export default function HomePage({ threatLevel, setThreatLevel }) {
  const [selectedAgents, setSelectedAgents] = useState({
    scoutToAnalyzer: true,
    analyzerToResponder: true,
    responderToEvolver: true,
    evolverToScout: true,
    allAgents: false,
  });

  return (
    <motion.div
      className="home-page"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <div className="home-grid">
        {/* Header Section */}
        <motion.div
          className="home-header"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <div className="header-content">
            <h2>Network Intelligence Center</h2>
            <p>Real-time threat monitoring and agent communication</p>
          </div>
        </motion.div>

        {/* Network Logs */}
        <NetworkLogs />

        {/* Communication Control */}
        <CommunicationToggle selectedAgents={selectedAgents} setSelectedAgents={setSelectedAgents} />
      </div>
    </motion.div>
  );
}
