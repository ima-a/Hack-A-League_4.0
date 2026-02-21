# SwarmShield

A distributed AI agent system for autonomous network threat detection, analysis, response, and learning. Built with CrewAI, integrating RL-based anomaly detection, GNNs for threat modeling, mirage deception, and genetic algorithm-driven evolution.

## Overview

SwarmShield uses a multi-agent architecture to:
- **Scout**: Perform network reconnaissance and anomaly detection
- **Analyzer**: Simulate threats and model attack graphs using GNNs
- **Responder**: Deploy mirage honeypots and SDN-based isolation
- **Evolver**: Optimize defense strategies via genetic algorithms

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SwarmShield                      │
│              (CrewAI Multi-Agent System)            │
└─────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
    ┌────────┐     ┌────────┐     ┌────────┐     ┌────────┐
    │ Scout  │     │Analyzer│     │Response│     │Evolver │
    │ Agent  │────▶│ Agent  │────▶│ Agent  │────▶│ Agent  │
    └────────┘     └────────┘     └────────┘     └────────┘
         │              │              │              │
         └──────────────┴──────────────┴──────────────┘
                         │
                    ┌────▼────┐
                    │ Feedback │
                    │  Loop    │
                    └──────────┘
```

## Features

- **RL-based Patrol**: Anomaly detection with reinforcement learning
- **GNN Threat Simulation**: Monte Carlo simulations on graph-structured networks
- **Mirage Deception**: Dynamic honeypot deployment
- **SDN Integration**: Software-defined network controls for isolation
- **Genetic Evolution**: DEAP-based strategy optimization
- **Live Packet Capture**: PyShark/Scapy integration for real-time monitoring
- **Dashboard**: Streamlit-based visualization (optional)

## Project Structure

```
swarmshield/
├── .gitignore
├── README.md
├── requirements.txt
├── .env                          # API keys (not committed)
├── .env.example                  # Template for .env
├── run.py                        # Entry point
├── docker-compose.yml            # Optional containerization
├── notebooks/
│   └── threat_model_exploration.ipynb
├── data/
│   └── sample_traffic.pcap
├── src/swarmshield/
│   ├── __init__.py
│   ├── main.py                   # Primary entry point
│   ├── crew.py                   # CrewAI crew definition
│   ├── config/
│   │   ├── agents.yaml
│   │   ├── tasks.yaml
│   │   └── tools_config.yaml
│   ├── agents/
│   │   ├── scout.py
│   │   ├── analyzer.py
│   │   ├── responder.py
│   │   └── evolver.py
│   ├── tools/
│   │   ├── patrol_tool.py
│   │   ├── threat_sim_tool.py
│   │   ├── response_tool.py
│   │   ├── evolution_tool.py
│   │   └── packet_capture_tool.py
│   ├── utils/
│   │   ├── logging.py
│   │   ├── config_loader.py
│   │   └── network_sim.py
│   └── demo/
│       ├── dashboard.py
│       └── attack_simulator.py
└── tests/
    ├── test_agents.py
    ├── test_tools.py
    └── test_crew.py
```

## Setup

### Prerequisites
- Python 3.9+
- LLM API key (OpenAI, Anthropic, etc.)
- Optional: Docker for containerized Mininet environment

### Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd swarmshield
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

### Running the Swarm

Simple demo run:
```bash
python run.py
```

Or with arguments:
```bash
python run.py --mode=demo --agents=scout,analyzer,responder --iterations=5
```

## Demo

The demo includes:
- Sample network traffic (sample_traffic.pcap)
- Mock Mininet network simulation
- Simulated attacks (nmap, hping3)
- Live agent interaction and response

Run the demo:
```bash
python run.py --mode=demo
```

Or access the optional Streamlit dashboard:
```bash
streamlit run src/swarmshield/demo/dashboard.py
```

## Testing

Run all tests:
```bash
pytest tests/
```

Run specific test file:
```bash
pytest tests/test_agents.py -v
```

## Documentation

- **Agents**: See [src/swarmshield/agents/](src/swarmshield/agents/) for agent implementations
- **Tools**: See [src/swarmshield/tools/](src/swarmshield/tools/) for tool implementations
- **Configs**: See [src/swarmshield/config/](src/swarmshield/config/) for YAML configurations
- **Notebooks**: See [notebooks/](notebooks/) for exploratory analysis and ML training

## Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Commit changes: `git commit -am 'Add my feature'`
3. Push to branch: `git push origin feature/my-feature`
4. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Contact

For questions or issues, please open a GitHub issue or contact the team.
