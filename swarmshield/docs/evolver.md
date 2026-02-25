# Mahoraga - Adaptive Defense Strategy Evolver

Source: src/swarmshield/agents/evolver.py
Class: Mahoraga (alias: EvolverAgent)

Named after the Divine General Mahoraga from Jujutsu Kaisen: "The being that adapts to all techniques."

Mahoraga uses a DEAP genetic algorithm to evolve Scout detection thresholds from real defense-cycle outcomes, minimizing false positives and false negatives over time.

## Genome (chromosome)

Each candidate solution is a list of 6 floats:

    Index  Name                           Default    Bounds               Unit
    0      ddos_pps_threshold             500        (50, 2000)           packets per second
    1      ddos_syn_threshold             300        (20, 1000)           SYN packets in window
    2      port_scan_unique_ip_thresh     20         (2, 100)             unique destination IPs
    3      port_scan_entropy_threshold    3.5        (1.0, 6.0)           bits (Shannon entropy)
    4      exfil_bps_threshold            500000     (10000, 2000000)     bytes per second
    5      confidence_threshold           0.60       (0.30, 0.90)         dimensionless

Genes 0 to 4 map directly onto Scout's detection threshold dict. Gene 5 sets the minimum confidence before Responder takes action.

## Fitness function

    fitness = (TP + TN) / (TP + TN + 2*FP + FN + epsilon)

FP is penalized 2x because blocking legitimate traffic is more disruptive than missing a threat. epsilon = 1e-9 prevents division by zero. Score is in range 0 to 1, higher is better.

## DEAP configuration

    POP_SIZE        30    (individuals per generation)
    N_GENERATIONS   20    (number of generations)
    CXPB            0.70  (crossover probability)
    MUTPB           0.30  (per-individual mutation probability)
    INDPB           0.30  (per-gene mutation probability)
    TOURNAMENT_K    3     (tournament selection size)
    Mutation op: Gaussian with per-gene sigma defined in MUT_SIGMA

Population is seeded so individual 0 is always DEFAULT_GENOME, giving the GA a known-good starting point.

## Lifecycle

    Defense cycle ends
        -> record_outcome(source_ip, stats, attack_type, confidence, action_taken)
           writes to swarmshield/runtime/mahoraga_outcomes.jsonl
        -> evolve() runs DEAP eaSimple for N_GENERATIONS
           saves best genome to swarmshield/runtime/mahoraga_best_strategy.json
        -> apply_to_agents(scout_agent) pushes evolved thresholds into ScoutAgent
        -> Next cycle uses evolved thresholds

### record_outcome

Appends one observation to `swarmshield/runtime/mahoraga_outcomes.jsonl`. The was_threat flag is inferred from action_taken:

    block, redirect_to_honeypot, quarantine  ->  was_threat = True
    monitor                                  ->  was_threat = False

### evolve() return value

    {
      "best_genome":          [500.0, 300.0, 20.0, 3.5, 500000.0, 0.60],
      "best_thresholds":      {"ddos_pps_threshold": 500.0, ...},
      "confidence_threshold": 0.60,
      "best_fitness":         0.8734,
      "generations_run":      20,
      "population_size":      30,
      "outcomes_used":        142,
      "timestamp":            "2025-01-01T00:00:00+00:00"
    }

If no real outcomes have been recorded yet, Mahoraga falls back to 12 built-in synthetic scenarios (3 DDoS, 3 PortScan, 2 Exfiltration, 4 Normal).

## Storage files

    swarmshield/runtime/mahoraga_outcomes.jsonl        - one JSON line per recorded defense-cycle outcome
    swarmshield/runtime/mahoraga_best_strategy.json    - latest evolve() result (full dict)

Both files are written under `swarmshield/runtime/`.

## Optional LLM enrichment

After each GA run, Mahoraga can send the evolved thresholds to Grok (via LLMClient) for a structured advisory review. The LLM returns threshold_assessment, blind_spots, recommended_tuning, adaptation_rating, and reasoning. This output is attached as llm_insight in the evolve() result. It is purely advisory and never changes the GA output.

## CrewAI tools

The Evolver exposes two CrewAI @tool functions in tools/evolution_tool.py:

    evolve_detection_thresholds(responder_summary_json)  - run GA and update thresholds
    get_current_thresholds()                             - load best saved thresholds

## Graceful degradation

If deap is not installed, evolve() returns the DEFAULT_GENOME result without raising an error. All other methods (record_outcome, load_outcomes, apply_to_agents) work without DEAP.

Install DEAP: pip install "deap==1.4.3"

## Backwards compatibility

EvolverAgent is an alias for Mahoraga. Existing imports using EvolverAgent continue to work.
