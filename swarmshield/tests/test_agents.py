"""
Unit tests for agents.
"""

import pytest
from src.swarmshield.agents import ScoutAgent, AnalyzerAgent, ResponderAgent, EvolverAgent


class TestScoutAgent:
    """Tests for ScoutAgent."""
    
    def test_scout_initialization(self):
        """Test scout agent initialization."""
        scout = ScoutAgent()
        assert scout.name == "Scout"
    
    def test_scan_network(self):
        """Test network scanning."""
        scout = ScoutAgent()
        result = scout.scan_network()
        assert isinstance(result, dict)
    
    def test_detect_anomalies(self):
        """Test anomaly detection."""
        scout = ScoutAgent()
        result = scout.detect_anomalies()
        assert isinstance(result, list)


class TestAnalyzerAgent:
    """Tests for AnalyzerAgent."""
    
    def test_analyzer_initialization(self):
        """Test analyzer agent initialization."""
        analyzer = AnalyzerAgent()
        assert analyzer.name == "Analyzer"
    
    def test_model_threat_graph(self):
        """Test threat graph modeling."""
        analyzer = AnalyzerAgent()
        result = analyzer.model_threat_graph([])
        assert isinstance(result, dict)


class TestResponderAgent:
    """Tests for ResponderAgent."""
    
    def test_responder_initialization(self):
        """Test responder agent initialization."""
        responder = ResponderAgent()
        assert responder.name == "Responder"
    
    def test_deploy_mirage(self):
        """Test mirage deployment."""
        responder = ResponderAgent()
        result = responder.deploy_mirage({})
        assert isinstance(result, dict)


class TestEvolverAgent:
    """Tests for EvolverAgent."""
    
    def test_evolver_initialization(self):
        """Test evolver agent initialization."""
        evolver = EvolverAgent()
        assert evolver.name == "Evolver"
    
    def test_create_population(self):
        """Test population creation."""
        evolver = EvolverAgent()
        result = evolver.create_population()
        assert isinstance(result, list)
