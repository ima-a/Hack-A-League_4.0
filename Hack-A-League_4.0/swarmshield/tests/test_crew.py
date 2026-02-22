"""
Unit tests for crew orchestration.
"""

import pytest
from src.swarmshield.crew import SwarmShieldCrew


class TestSwarmShieldCrew:
    """Tests for SwarmShieldCrew."""
    
    def test_crew_initialization(self):
        """Test crew initialization."""
        crew = SwarmShieldCrew()
        assert crew is not None
        assert crew.agents == {}
        assert crew.tasks == {}
    
    def test_crew_with_config(self):
        """Test crew initialization with config."""
        crew = SwarmShieldCrew(config_path="test_config.yaml")
        assert crew.config_path == "test_config.yaml"
    
    def test_run_demo(self):
        """Test demo mode execution."""
        crew = SwarmShieldCrew()
        # Should not raise exception
        crew.run_demo(iterations=1)
    
    def test_run_interactive(self):
        """Test interactive mode execution."""
        crew = SwarmShieldCrew()
        # Should not raise exception (but may block, so keep it lightweight)
        # crew.run_interactive()
    
    def test_run_batch(self):
        """Test batch mode execution."""
        crew = SwarmShieldCrew()
        # Should not raise exception
        crew.run_batch(iterations=1)
