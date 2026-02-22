# Mahoraga — Adaptive Defense Strategy Evolver

Source: `src/swarmshield/agents/evolver.py`  
Class: `Mahoraga` (alias: `EvolverAgent`)

> **Named after the Divine General Mahoraga** (*Jujutsu Kaisen*): *"The being that adapts to all techniques."*
>
> Mahoraga uses a **DEAP genetic algorithm** to evolve Scout's detection thresholds from real defense-cycle outcomes, minimising both false positives and false negatives over time. No manual tuning required — the system learns from what it gets right and wrong.

---

## Genome (chromosome)

Each candidate solution is a fixed-length list of six floats:

| Index | Gene name                     | Default       | Bounds                  | Unit        |
|-------|-------------------------------|---------------|-------------------------|-------------|
| 0     | `ddos_pps_threshold`          | 500           | [50, 2 000]             | packets/sec |
| 1     | `ddos_syn_threshold`          | 300           | [20, 1 000]             | SYN pkts    |
| 2     | `port_scan_unique_ip_thresh`  | 20            | [2, 100]                | dest IPs    |
| 3     | `port_scan_entropy_threshold` | 3.5           | [1.0, 6.0]              | bits        |
| 4     | `exfil_bps_threshold`         | 500 000       | [10 000, 2 000 000]     | bytes/sec   |
| 5     | `confidence_threshold`        | 0.60          | [0.30, 0.90]            | [0–1]       |

Genes 0–4 map directly onto Scout's `_DEFAULT_THRESHOLDS` dict.  
Gene 5 is the minimum confidence Scout must report before Responder acts.

---

## Fitness function

$$\text{fitness} = \frac{TP + TN}{TP + TN + 2 \cdot FP + FN + \varepsilon}$$

- **FP penalised 2×** — blocking legitimate traffic is more disruptive than missing a threat.
- ε = 1e-9 prevents division by zero.
- Score is in [0, 1]; higher is better.

Each evaluation re-runs Scout's `monte_carlo_estimate` with the genome's thresholds against every recorded outcome and counts TP / TN / FP / FN.

---

## DEAP configuration

| Parameter       | Value  | Description                             |
|-----------------|--------|-----------------------------------------|
| `POP_SIZE`      | 30     | Individuals per generation              |
| `N_GENERATIONS` | 20     | Number of generations                   |
| `CXPB`          | 0.70   | Crossover (blend, α=0.5) probability    |
| `MUTPB`         | 0.30   | Per-individual mutation probability     |
| `INDPB`         | 0.30   | Per-gene mutation probability           |
| `TOURNAMENT_K`  | 3      | Tournament selection size               |
| Mutation op     | `mutGaussian` | σ per gene (see `MUT_SIGMA`)    |

Population is seeded so individual[0] is always `DEFAULT_GENOME`, giving the GA a known-good starting point.

---

## Lifecycle

```
[Defense cycle]
     │
     ▼
record_outcome(source_ip, stats, attack_type, confidence, action_taken)
     │   writes to mahoraga_outcomes.jsonl
     ▼
evolve(outcomes=None)          ← call periodically or on demand
     │   runs DEAP eaSimple for N_GENERATIONS
     │   saves best genome to mahoraga_best_strategy.json
     ▼
apply_to_agents(scout_agent)
     │   scout_agent.thresholds ← best_thresholds
     ▼
[Next cycle uses evolved thresholds]
```

### `record_outcome(...)`

Appends one observation to `mahoraga_outcomes.jsonl`.  
`was_threat` is **inferred from `action_taken`**:

| action_taken            | was_threat |
|-------------------------|------------|
| block                   | True       |
| redirect_to_honeypot    | True       |
| quarantine              | True       |
| monitor                 | False      |

### `evolve(outcomes=None, verbose=False) -> dict`

Runs the genetic algorithm. Returns:

```json
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
```

If no outcomes have been recorded yet, Mahoraga falls back to 12 built-in **synthetic scenarios** (3 DDoS, 3 PortScan, 2 Exfiltration, 4 Normal) so it can evolve from day one.

### `apply_to_agents(scout_agent)`

Pushes the best-evolved thresholds live into a running `ScoutAgent` instance.  
Returns `True` if thresholds were applied, `False` if `evolve()` has never been called.

---

## Storage files

| File                           | Content                                  |
|--------------------------------|------------------------------------------|
| `mahoraga_outcomes.jsonl`      | One JSON object per line, one per cycle  |
| `mahoraga_best_strategy.json`  | Latest `evolve()` result (full dict)     |

Both files are written at `PROJECT_ROOT` (repo root).

---

## Backwards compatibility

`EvolverAgent = Mahoraga` — existing code using `EvolverAgent` continues to work unchanged.

Legacy method shims:

| Old method                          | Maps to                       |
|-------------------------------------|-------------------------------|
| `evaluate_fitness(strategy_dict)`   | `evaluate_genome(genome)`     |
| `create_population_legacy()`        | `create_population()`         |
| `evolve_strategies(outcomes)`       | `[evolve(outcomes=outcomes)]` |

---

## Graceful degradation

If `deap` is not installed, `evolve()` returns the `DEFAULT_GENOME` result without error.  
All other methods (`record_outcome`, `load_outcomes`, `apply_to_agents`) work without DEAP.

Install DEAP:

```bash
pip install "deap==1.4.3"
```
