"""
Unit tests for agents.
"""

import pytest
from src.swarmshield.agents import ScoutAgent, AnalyzerAgent, ResponderAgent, Mahoraga, EvolverAgent


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


class TestMahoraga:
    """Tests for Mahoraga (Adaptive Defense Strategy Evolver)."""

    def test_initialization(self):
        """Mahoraga has proper name."""
        m = Mahoraga()
        assert m.name == "Mahoraga"

    def test_evolver_agent_alias(self):
        """EvolverAgent is a backwards-compat alias for Mahoraga."""
        assert EvolverAgent is Mahoraga

    def test_create_population_returns_list(self):
        """create_population returns a non-empty list."""
        m = Mahoraga()
        pop = m.create_population(size=5)
        assert isinstance(pop, list)
        assert len(pop) == 5

    def test_create_population_seeds_defaults(self):
        """First individual is seeded from DEFAULT_GENOME."""
        from src.swarmshield.agents.evolver import DEFAULT_GENOME
        m = Mahoraga()
        pop = m.create_population(size=10, seed_defaults=True)
        first = list(pop[0])
        assert first == pytest.approx(DEFAULT_GENOME, rel=1e-6)

    def test_evaluate_genome_synthetic(self):
        """evaluate_genome on DEFAULT_GENOME with synthetic scenarios returns a float in [0,1]."""
        from src.swarmshield.agents.evolver import DEFAULT_GENOME, _SYNTHETIC_SCENARIOS
        m = Mahoraga()
        fit = m.evaluate_genome(DEFAULT_GENOME, outcomes=list(_SYNTHETIC_SCENARIOS))
        assert isinstance(fit, float)
        assert 0.0 <= fit <= 1.0

    def test_record_outcome_creates_file(self, tmp_path):
        """record_outcome writes a JSONL entry to outcomes_file."""
        import json
        outfile = str(tmp_path / "outcomes.jsonl")
        m = Mahoraga(outcomes_file=outfile)
        m.record_outcome(
            source_ip="1.2.3.4",
            stats={"packets_per_second": 900},
            attack_type="DDoS",
            confidence=0.85,
            action_taken="block",
        )
        with open(outfile) as fh:
            record = json.loads(fh.readline())
        assert record["source_ip"] == "1.2.3.4"
        assert record["was_threat"] is True

    def test_record_outcome_monitor_not_threat(self, tmp_path):
        """monitor action is inferred as was_threat=False."""
        import json
        outfile = str(tmp_path / "outcomes.jsonl")
        m = Mahoraga(outcomes_file=outfile)
        m.record_outcome(
            source_ip="5.6.7.8",
            stats={"packets_per_second": 30},
            attack_type="Normal",
            confidence=0.40,
            action_taken="monitor",
        )
        with open(outfile) as fh:
            record = json.loads(fh.readline())
        assert record["was_threat"] is False

    def test_load_outcomes_empty(self, tmp_path):
        """load_outcomes returns [] when file doesn't exist."""
        m = Mahoraga(outcomes_file=str(tmp_path / "missing.jsonl"))
        assert m.load_outcomes() == []

    def test_evolve_returns_expected_keys(self, tmp_path):
        """evolve() returns a dict with all required keys."""
        m = Mahoraga(
            outcomes_file=str(tmp_path / "outcomes.jsonl"),
            best_genome_file=str(tmp_path / "best.json"),
            pop_size=6,
            n_generations=3,
        )
        result = m.evolve()
        for key in ("best_genome", "best_thresholds", "confidence_threshold",
                    "best_fitness", "generations_run", "outcomes_used", "timestamp"):
            assert key in result

    def test_evolve_best_fitness_range(self, tmp_path):
        """Evolved fitness should be in [0, 1]."""
        m = Mahoraga(
            outcomes_file=str(tmp_path / "outcomes.jsonl"),
            best_genome_file=str(tmp_path / "best.json"),
            pop_size=6,
            n_generations=3,
        )
        result = m.evolve()
        assert 0.0 <= result["best_fitness"] <= 1.0

    def test_apply_to_agents_no_strategy(self, tmp_path):
        """apply_to_agents returns False when no best strategy saved yet."""
        m = Mahoraga(best_genome_file=str(tmp_path / "best.json"))
        scout = ScoutAgent()
        assert m.apply_to_agents(scout) is False

    def test_apply_to_agents_updates_scout(self, tmp_path):
        """apply_to_agents pushes evolved thresholds into ScoutAgent."""
        m = Mahoraga(
            outcomes_file=str(tmp_path / "outcomes.jsonl"),
            best_genome_file=str(tmp_path / "best.json"),
            pop_size=6,
            n_generations=3,
        )
        m.evolve()
        scout = ScoutAgent()
        result = m.apply_to_agents(scout)
        assert result is True
        assert isinstance(scout.thresholds, dict)
