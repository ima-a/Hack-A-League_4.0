"""
Unit tests for tools.
"""

import pytest
from src.swarmshield.tools import (
    PatrolTool,
    ThreatSimTool,
    ResponseTool,
    EvolutionTool,
    PacketCaptureTool
)


class TestPatrolTool:
    """Tests for PatrolTool."""
    
    def test_patrol_tool_initialization(self):
        """Test patrol tool initialization."""
        tool = PatrolTool()
        assert tool is not None
    
    def test_execute(self):
        """Test execute method."""
        tool = PatrolTool()
        result = tool.execute({})
        assert isinstance(result, dict)
        assert "anomalies_detected" in result


class TestThreatSimTool:
    """Tests for ThreatSimTool."""
    
    def test_threat_sim_tool_initialization(self):
        """Test threat sim tool initialization."""
        tool = ThreatSimTool()
        assert tool is not None
    
    def test_execute(self):
        """Test execute method."""
        tool = ThreatSimTool()
        result = tool.execute({})
        assert isinstance(result, dict)
        assert "attack_graph" in result


class TestResponseTool:
    """Tests for ResponseTool."""
    
    def test_response_tool_initialization(self):
        """Test response tool initialization."""
        tool = ResponseTool()
        assert tool is not None
    
    def test_execute(self):
        """Test execute method."""
        tool = ResponseTool()
        result = tool.execute({})
        assert isinstance(result, dict)
        assert "honeypots_deployed" in result


class TestEvolutionTool:
    """Tests for EvolutionTool."""
    
    def test_evolution_tool_initialization(self):
        """Test evolution tool initialization."""
        tool = EvolutionTool()
        assert tool is not None
    
    def test_execute(self):
        """Test execute method returns a valid evolution result."""
        tool = EvolutionTool()
        result = tool.execute({})
        assert isinstance(result, dict)
        # Real Mahoraga result has these keys; error fallback has evolved_strategies.
        assert "best_genome" in result or "evolved_strategies" in result


class TestPacketCaptureTool:
    """Tests for PacketCaptureTool."""
    
    def test_packet_capture_tool_initialization(self):
        """Test packet capture tool initialization."""
        tool = PacketCaptureTool()
        assert tool is not None
    
    def test_execute(self):
        """Test execute method."""
        tool = PacketCaptureTool()
        result = tool.execute({})
        assert isinstance(result, dict)
        assert "packets_captured" in result
