import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import Navigation from './components/Navigation';
import HomePage from './pages/HomePage';
import DocumentationPage from './pages/DocumentationPage';
import './styles/App.css';

function App() {
  const [currentPage, setCurrentPage] = useState('home');
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
      <Navigation currentPage={currentPage} setCurrentPage={setCurrentPage} threatLevel={threatLevel} />
      <main className="main-content">
        {currentPage === 'home' && <HomePage threatLevel={threatLevel} setThreatLevel={setThreatLevel} />}
        {currentPage === 'documentation' && <DocumentationPage />}
      </main>
    </div>
  );
}

export default App;
