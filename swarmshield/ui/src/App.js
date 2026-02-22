import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import Dashboard from './components/Dashboard';
import Navigation from './components/Navigation';
import './styles/App.css';

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [threatLevel, setThreatLevel] = useState(Math.random() > 0.7 ? 'critical' : 'normal');

  useEffect(() => {
    // Simulate threat level changes
    const interval = setInterval(() => {
      setThreatLevel(Math.random() > 0.8 ? 'critical' : Math.random() > 0.5 ? 'medium' : 'normal');
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      <Navigation activeView={activeView} setActiveView={setActiveView} threatLevel={threatLevel} />
      <main className="main-content">
        {activeView === 'dashboard' && <Dashboard threatLevel={threatLevel} setThreatLevel={setThreatLevel} />}
      </main>
    </div>
  );
}

export default App;
