import React from 'react';
import { motion } from 'framer-motion';
import AgentDocumentation from '../components/AgentDocumentation';
import '../styles/DocumentationPage.css';

export default function DocumentationPage() {
  return (
    <motion.div
      className="documentation-page"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <div className="doc-page-container">
        <motion.div
          className="doc-page-header"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <h1>Agent Documentation Hub</h1>
          <p>Complete guide to SwarmShield's autonomous defense agents</p>
        </motion.div>

        <AgentDocumentation />
      </div>
    </motion.div>
  );
}
