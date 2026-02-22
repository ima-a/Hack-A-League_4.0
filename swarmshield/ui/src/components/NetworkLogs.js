import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FiTrash2 } from 'react-icons/fi';
import '../styles/NetworkLogs.css';

export default function NetworkLogs() {
  const [logs, setLogs] = useState([]);

  const threatTypes = ['DDoS', 'Port Scan', 'Exfiltration', 'Lateral Movement', 'Brute Force', 'Malware'];
  const sources = ['192.168.1.45', '10.0.0.88', '172.16.0.12', '192.168.2.99', '10.1.1.55'];
  const destinations = ['192.168.1.100', '10.0.0.1', '172.16.0.50', '192.168.2.1', '10.1.1.1'];

  useEffect(() => {
    const generateLog = () => {
      const log = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        source: sources[Math.floor(Math.random() * sources.length)],
        destination: destinations[Math.floor(Math.random() * destinations.length)],
        threatType: threatTypes[Math.floor(Math.random() * threatTypes.length)],
        severity: ['Low', 'Medium', 'High', 'Critical'][Math.floor(Math.random() * 4)],
        packets: Math.floor(Math.random() * 5000),
        bytes: Math.floor(Math.random() * 1000000),
        status: Math.random() > 0.3 ? 'Blocked' : 'Detected',
      };
      return log;
    };

    const interval = setInterval(() => {
      setLogs((prev) => [generateLog(), ...prev.slice(0, 19)]);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical':
        return '#ff1744';
      case 'High':
        return '#ff9800';
      case 'Medium':
        return '#ffeb3b';
      case 'Low':
        return '#4caf50';
      default:
        return '#ffffff';
    }
  };

  const getStatusColor = (status) => {
    return status === 'Blocked' ? '#ff1744' : '#ff9800';
  };

  return (
    <motion.div
      className="network-logs"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
    >
      <div className="logs-header">
        <h3>🔍 Network Logs</h3>
        <motion.button
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setLogs([])}
          className="clear-logs-btn"
        >
          <FiTrash2 size={16} />
        </motion.button>
      </div>

      <div className="logs-container">
        <div className="logs-table-header">
          <div className="log-col-time">Time</div>
          <div className="log-col-source">Source IP</div>
          <div className="log-col-dest">Destination</div>
          <div className="log-col-threat">Threat Type</div>
          <div className="log-col-severity">Severity</div>
          <div className="log-col-packets">Packets</div>
          <div className="log-col-status">Status</div>
        </div>

        <AnimatePresence>
          {logs.length > 0 ? (
            logs.map((log, idx) => (
              <motion.div
                key={log.id}
                className="log-row"
                initial={{ x: -20, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: 20, opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <div className="log-col-time">{log.timestamp}</div>
                <div className="log-col-source">{log.source}</div>
                <div className="log-col-dest">{log.destination}</div>
                <div className="log-col-threat">{log.threatType}</div>
                <div
                  className="log-col-severity"
                  style={{ color: getSeverityColor(log.severity) }}
                >
                  {log.severity}
                </div>
                <div className="log-col-packets">{log.packets}</div>
                <div
                  className="log-col-status"
                  style={{ color: getStatusColor(log.status) }}
                >
                  {log.status}
                </div>
              </motion.div>
            ))
          ) : (
            <div className="logs-empty">No threats detected</div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
