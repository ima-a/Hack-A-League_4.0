"""
SwarmShield Crew Configuration
================================
Defines the multi-agent crew, process flow, and task orchestration using CrewAI.

Pipeline (sequential):
  1. Scout   — detect network threats via Monte Carlo analysis
  2. Analyzer — build threat graph and run propagation simulation
  3. Responder — apply minimum-necessary defense actions
  4. Evolver  — evolve Scout thresholds from defense-cycle outcomes (Mahoraga)
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CrewAI imports — graceful fallback when package is not yet installed
# ---------------------------------------------------------------------------
try:
    from crewai import Agent, Task, Crew, Process
    _CREWAI_AVAILABLE = True
except ImportError:
    logger.error(
        "CrewAI is not installed. Run: pip install 'crewai>=0.80.0'"
    )
    _CREWAI_AVAILABLE = False
    Agent = Task = Crew = Process = None  # type: ignore[assignment,misc]

# LLM helper — optional; agents fall back to env-var-configured LLM
try:
    from crewai import LLM as CrewLLM
    _CREWAI_LLM_AVAILABLE = True
except ImportError:
    CrewLLM = None  # type: ignore[assignment,misc]
    _CREWAI_LLM_AVAILABLE = False

# ---------------------------------------------------------------------------
# Tool imports
# ---------------------------------------------------------------------------
try:
    from .tools.scout_tool import (
        run_monte_carlo_analysis,
        scan_network_for_threats,
        simulate_attack_traffic,
    )
    from .tools.analyzer_tool import (
        build_threat_graph,
        run_propagation_simulation,
        full_threat_analysis,
    )
    from .tools.responder_tool import (
        apply_defense_actions,
        block_ip_address,
        get_active_blocks,
    )
    from .tools.evolution_tool import (
        evolve_detection_thresholds,
        get_current_thresholds,
    )
    _TOOLS_AVAILABLE = True
except ImportError as _tools_err:
    logger.error("Could not import SwarmShield tools: %s", _tools_err)
    _TOOLS_AVAILABLE = False


# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

def _build_llm():
    """
    Build a CrewAI LLM object.

    Priority:
    1. XAI_API_KEY  → Grok-2 via OpenAI-compatible xAI endpoint
    2. OPENAI_API_KEY → OpenAI (or any OpenAI-compat provider via OPENAI_BASE_URL)
    3. Fallback     → placeholder model — construction succeeds but kickoff()
                      will fail gracefully; useful for tests / offline demos.

    CrewAI 1.x requires a valid LLM object on every Agent at construction time.
    Passing api_key="sk-placeholder" defers the auth error to call time so the
    crew graph can be inspected / tested without live credentials.
    """
    if not _CREWAI_LLM_AVAILABLE or CrewLLM is None:
        return None

    xai_key = os.environ.get("XAI_API_KEY", "").strip()
    if xai_key:
        try:
            return CrewLLM(
                model="openai/grok-2-1212",
                base_url="https://api.x.ai/v1",
                api_key=xai_key,
                temperature=0.0,
                max_tokens=2000,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build Grok LLM: %s", exc)

    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if openai_key:
        model = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o-mini")
        base_url = os.environ.get("OPENAI_BASE_URL", "")
        try:
            kwargs: dict = {"model": f"openai/{model}", "api_key": openai_key, "temperature": 0.0}
            if base_url:
                kwargs["base_url"] = base_url
            return CrewLLM(**kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build OpenAI LLM: %s", exc)

    # No real key found
    # Build a placeholder LLM so Agent construction succeeds.  Actual
    # kickoff() calls will fail with an auth error at the first tool call —
    # which is the correct and expected behaviour when no key is configured.
    logger.warning(
        "No XAI_API_KEY or OPENAI_API_KEY found. "
        "Crew will build but kickoff() requires a real API key. "
        "Set XAI_API_KEY (Grok) or OPENAI_API_KEY in your .env file."
    )
    try:
        return CrewLLM(model="openai/gpt-4o-mini", api_key="sk-placeholder")
    except Exception:  # noqa: BLE001
        return None


# ===========================================================================
# SwarmShieldCrew
# ===========================================================================

class SwarmShieldCrew:
    """
    Main crew orchestrator for SwarmShield agents.

    Builds a CrewAI Crew with four agents running in sequential process order:
      Scout → Analyzer → Responder → Evolver (Mahoraga)

    Usage::

        crew = SwarmShieldCrew()
        result = crew.build().kickoff(inputs={"traffic_input": "..."})
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        # Transparency reporter — instantiated here so step/task counts persist
        # across iterations in batch mode.  Disabled via TRANSPARENCY_CONSOLE=false.
        try:
            from .utils.transparency import TransparencyReporter
            self._reporter: Optional["TransparencyReporter"] = TransparencyReporter()
        except Exception:  # noqa: BLE001
            self._reporter = None
        logger.info("SwarmShieldCrew initialised")

    # ------------------------------------------------------------------
    # Core builder
    # ------------------------------------------------------------------

    def build(self) -> "Crew":
        """
        Instantiate all CrewAI Agents, Tasks, and the Crew.

        Returns the configured Crew, ready for .kickoff().
        Raises RuntimeError if CrewAI is not installed.
        """
        if not _CREWAI_AVAILABLE:
            raise RuntimeError(
                "CrewAI is not installed. Run: pip install 'crewai>=0.80.0'"
            )

        llm = _build_llm()
        # Always pass llm= so CrewAI never falls back to environment discovery,
        # which raises if OPENAI_API_KEY is absent at import time.
        llm_kwargs = {"llm": llm} if llm is not None else {}

        # ---- Agents -------------------------------------------------------

        scout_agent = Agent(
            role="Network Traffic Scout",
            goal=(
                "Detect anomalous network traffic patterns and classify threats "
                "using Monte Carlo simulation. Produce a structured JSON threat "
                "report covering every suspicious source IP."
            ),
            backstory=(
                "You are SwarmShield's vigilant front-line sentinel. You monitor "
                "all inbound packet flows, compute per-source traffic statistics, "
                "and run Monte Carlo simulations to estimate the probability that "
                "each source IP is executing a DDoS, port scan, or data exfiltration. "
                "You understand attack kill-chain stages and always report confidence "
                "scores alongside attack classifications. You never block traffic "
                "yourself — your job is pure intelligence gathering."
            ),
            tools=[
                scan_network_for_threats,
                simulate_attack_traffic,
                run_monte_carlo_analysis,
            ],
            verbose=True,
            allow_delegation=False,
            **llm_kwargs,
        )

        analyzer_agent = Agent(
            role="Threat Graph Analyzer",
            goal=(
                "Correlate Scout threat detections into an attack graph, run "
                "Monte Carlo lateral-movement propagation simulation, assess "
                "overall risk level, and produce ranked containment recommendations."
            ),
            backstory=(
                "You are SwarmShield's graph-theory and threat-correlation specialist. "
                "You convert raw per-IP threat observations from the Scout into a "
                "directed attack graph where nodes are attacker IPs and edges represent "
                "likely lateral-movement paths. You then run Monte Carlo simulations "
                "to compute how far an attacker could propagate through the network. "
                "Your output is a precise risk assessment with ranked IP-level recommendations "
                "for the Responder to act on."
            ),
            tools=[
                full_threat_analysis,
                build_threat_graph,
                run_propagation_simulation,
            ],
            verbose=True,
            allow_delegation=False,
            **llm_kwargs,
        )

        responder_agent = Agent(
            role="Autonomous Defense Responder",
            goal=(
                "Apply the minimum-sufficient defense action to neutralise each "
                "confirmed threat without disrupting legitimate traffic. "
                "Prefer rate-limiting over blocking when confidence is borderline. "
                "Log every action taken and return a structured action summary."
            ),
            backstory=(
                "You are SwarmShield's precision firewall operator. You receive "
                "ranked threat recommendations from the Analyzer and translate "
                "them into concrete network enforcement actions: block, quarantine, "
                "redirect to honeypot, rate-limit, or monitor. You always apply "
                "the least-destructive action that neutralises the threat. "
                "In demo / dry-run mode you simulate all actions without touching "
                "the actual firewall."
            ),
            tools=[
                apply_defense_actions,
                block_ip_address,
                get_active_blocks,
            ],
            verbose=True,
            allow_delegation=False,
            **llm_kwargs,
        )

        evolver_agent = Agent(
            role="Adaptive Threshold Evolver (Mahoraga)",
            goal=(
                "After each defense cycle, evolve the Scout's detection thresholds "
                "using a genetic algorithm to minimise both false positives and "
                "false negatives. Return the new best genome and updated thresholds."
            ),
            backstory=(
                "You are Mahoraga — named after the Divine General who adapts to every "
                "technique. You use DEAP genetic algorithms to continuously evolve "
                "SwarmShield's detection sensitivity. After each defense cycle you "
                "record outcomes (TP/TN/FP/FN) and run a generational GA to find "
                "the threshold genome that maximises detection accuracy. You penalise "
                "false positives 2× because blocking legitimate traffic is worse than "
                "missing a threat. Your evolved thresholds are pushed to Scout live."
            ),
            tools=[
                evolve_detection_thresholds,
                get_current_thresholds,
            ],
            verbose=True,
            allow_delegation=False,
            **llm_kwargs,
        )

        # ---- Tasks --------------------------------------------------------

        task_scout = Task(
            description=(
                "Analyse the network for active threats. Use the simulate_attack_traffic "
                "tool to generate a representative traffic sample (attack_type='mixed'), "
                "then use scan_network_for_threats to detect anomalies. "
                "The current traffic scenario is: {traffic_input}. "
                "Return a complete JSON threat report listing all detected threats "
                "with source_ip, attack_type, confidence, and monte_carlo scores."
            ),
            expected_output=(
                "A JSON object with keys: threats_detected (int), threats (list of "
                "threat dicts each containing source_ip, attack_type, confidence, "
                "monte_carlo, timestamp)."
            ),
            agent=scout_agent,
        )

        task_analyze = Task(
            description=(
                "Take the Scout threat report from the previous task and perform "
                "full threat correlation analysis. Use full_threat_analysis to build "
                "the attack graph and run Monte Carlo propagation simulation. "
                "Identify coordinated attacks, assess lateral movement risk, and "
                "produce ranked IP-level action recommendations."
            ),
            expected_output=(
                "A JSON object with keys: threat_graph (nodes, edges, summary), "
                "simulation_results (list), risk_assessment (risk_level, risk_score, "
                "avg_spread, top_threats, recommendations)."
            ),
            agent=analyzer_agent,
            context=[task_scout],
        )

        task_respond = Task(
            description=(
                "Apply defense actions based on the Analyzer's risk report. "
                "Use apply_defense_actions with the full analyzer output JSON. "
                "For confirmed threats (confidence >= 0.60), apply the recommended "
                "action. For borderline threats (0.40-0.60), use rate_limit. "
                "Below 0.40, monitor only. Log every action and return a summary."
            ),
            expected_output=(
                "A JSON object with keys: actions_applied (list of dicts each with "
                "ip, action, success, mode), risk_level, live_mode (bool), "
                "summary (string), timestamp."
            ),
            agent=responder_agent,
            context=[task_analyze],
            # Human approval loop: when enabled, CrewAI pauses after the
            # Responder task and shows its output to the operator who can
            # accept, reject, or add instructions before execution continues.
            human_input=os.environ.get("HUMAN_APPROVAL", "false").lower() == "true",
        )

        task_evolve = Task(
            description=(
                "Use the Responder's action summary from the previous task as "
                "defense-cycle outcome data. Call evolve_detection_thresholds with "
                "the responder summary JSON to run the Mahoraga genetic algorithm. "
                "Also call get_current_thresholds to show what thresholds are active. "
                "Return the evolved genome and updated Scout thresholds."
            ),
            expected_output=(
                "A JSON object with keys: best_thresholds (dict of threshold names "
                "and values), confidence_threshold (float), best_fitness (float), "
                "generations_run (int), outcomes_used (int), llm_insight (dict or null)."
            ),
            agent=evolver_agent,
            context=[task_respond],
        )

        # ---- Crew assembly ------------------------------------------------

        _step_cb = self._reporter.on_agent_step   if self._reporter else None
        _task_cb = self._reporter.on_task_complete if self._reporter else None

        crew = Crew(
            agents=[scout_agent, analyzer_agent, responder_agent, evolver_agent],
            tasks=[task_scout, task_analyze, task_respond, task_evolve],
            process=Process.sequential,
            verbose=True,
            step_callback=_step_cb,
            task_callback=_task_cb,
        )

        logger.info(
            "SwarmShield crew assembled: %d agents, %d tasks, process=sequential",
            len(crew.agents), len(crew.tasks),
        )
        return crew

    # ------------------------------------------------------------------
    # A2A message bus wiring
    # ------------------------------------------------------------------

    def _setup_bus_subscriptions(self) -> None:
        """
        Subscribe to all A2A message-bus topics so that events published
        by CrewAI tools during task execution are captured and logged.

        This bridges the CrewAI sequential orchestration layer with the
        pub/sub A2A bus used by the underlying agent objects.  Subscribers
        here are intentionally lightweight (log-only); heavy work belongs
        inside the agents themselves.
        """
        try:
            from .utils.message_bus import (
                get_bus, reset_bus,
                TOPIC_SCOUT_TICK, TOPIC_SCOUT_EARLY_WARNING,
                TOPIC_ANALYZER_PREASSESS, TOPIC_ANALYZER_ASSESSMENT,
                TOPIC_RESPONDER_ACTION, TOPIC_MAHORAGA_EVOLVED,
            )
        except ImportError:
            logger.debug("message_bus unavailable — skipping bus wiring")
            return

        bus = get_bus()

        def _on_scout_tick(msg: dict) -> None:
            n = len(msg.get("confirmed_threats", []))
            logger.info("[A2A] scout.tick — %d confirmed threat(s)", n)

        def _on_early_warning(msg: dict) -> None:
            ips = msg.get("ips", [])
            logger.warning("[A2A] scout.early_warning — suspicious IPs: %s", ips)

        def _on_pre_assess(msg: dict) -> None:
            n = msg.get("total_early_warnings", 0)
            logger.info("[A2A] analyzer.pre_assessment — %d early warning(s)", n)

        def _on_assessment(msg: dict) -> None:
            level = msg.get("risk_level", "unknown")
            score = msg.get("risk_score", 0.0)
            logger.info("[A2A] analyzer.assessment — risk=%s score=%.3f", level, score)

        def _on_responder_action(msg: dict) -> None:
            ip     = msg.get("source_ip", "?")
            action = msg.get("action", "?")
            ok     = msg.get("success", True)
            logger.info("[A2A] responder.action — %s on %s success=%s", action, ip, ok)

        def _on_evolved(msg: dict) -> None:
            fit = msg.get("best_fitness", 0.0)
            gen = msg.get("generations_run", 0)
            logger.info("[A2A] mahoraga.evolved — fitness=%.4f generations=%d", fit, gen)

        bus.subscribe(TOPIC_SCOUT_TICK,         _on_scout_tick)
        bus.subscribe(TOPIC_SCOUT_EARLY_WARNING, _on_early_warning)
        bus.subscribe(TOPIC_ANALYZER_PREASSESS,  _on_pre_assess)
        bus.subscribe(TOPIC_ANALYZER_ASSESSMENT, _on_assessment)
        bus.subscribe(TOPIC_RESPONDER_ACTION,    _on_responder_action)
        bus.subscribe(TOPIC_MAHORAGA_EVOLVED,    _on_evolved)

        logger.info(
            "[A2A] Message bus wired — subscribed to %d topic(s): %s",
            len(bus.topics()), ", ".join(bus.topics()),
        )

    def _start_honeypot_bridge(self) -> None:
        """
        Start the HoneypotBridge Flask server in a background daemon thread.

        Only starts when HONEYPOT_BRIDGE_ENABLED=true is set in the environment
        (or in live mode, i.e. LIVE_MODE=true).  Safe to call multiple times —
        subsequent calls are silently skipped if the bridge is already running.

        The bridge listens on HONEYPOT_BRIDGE_HOST:HONEYPOT_BRIDGE_PORT
        (default 0.0.0.0:5001) for POST /honeypot_event callbacks from a
        partner honeypot.  Each received event is fed to Mahoraga so the
        genetic evolver has real ground-truth labels.
        """
        live_mode    = os.environ.get("LIVE_MODE",               "false").lower() == "true"
        bridge_on    = os.environ.get("HONEYPOT_BRIDGE_ENABLED", "false").lower() == "true"

        if not (live_mode or bridge_on):
            logger.debug(
                "HoneypotBridge not started — set HONEYPOT_BRIDGE_ENABLED=true "
                "(or LIVE_MODE=true) to enable it."
            )
            return

        # Avoid starting twice on repeated crew builds
        if getattr(SwarmShieldCrew, "_bridge_started", False):
            logger.debug("HoneypotBridge already running — skipping.")
            return

        try:
            from .agents.honeypot_bridge import run_bridge
            import threading

            host = os.environ.get("HONEYPOT_BRIDGE_HOST", "0.0.0.0")
            port = int(os.environ.get("HONEYPOT_BRIDGE_PORT", "5001"))

            t = threading.Thread(
                target=run_bridge,
                kwargs={"host": host, "port": port},
                daemon=True,
                name="honeypot-bridge",
            )
            t.start()
            SwarmShieldCrew._bridge_started = True
            logger.info(
                "HoneypotBridge started on %s:%d (background thread) — "
                "POST /honeypot_event to feed Mahoraga", host, port,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not start HoneypotBridge: %s", exc)

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def run_demo(self, iterations: int = 1) -> None:
        """Run demo mode with simulated attack scenarios."""
        logger.info("Running SwarmShield demo mode (%d iteration(s))", iterations)
        self._setup_bus_subscriptions()
        self._start_honeypot_bridge()
        if self._reporter:
            self._reporter.subscribe_to_bus()
        scenarios = [
            "SYN-flood DDoS from 10.0.0.1 targeting internal web server 192.168.1.100",
            "Horizontal port scan from 10.0.0.2 across 192.168.1.0/24 subnet",
            "Mixed attack: DDoS from 10.0.0.1 and port scan from 10.0.0.2 simultaneously",
        ]
        for i in range(iterations):
            scenario = scenarios[i % len(scenarios)]
            logger.info("Iteration %d/%d — scenario: %s", i + 1, iterations, scenario)
            try:
                if self._reporter:
                    self._reporter.print_banner(scenario)
                crew = self.build()
                result = crew.kickoff(inputs={"traffic_input": scenario})
                if self._reporter:
                    self._reporter.print_summary()
                logger.info("Iteration %d complete. Result preview: %s",
                            i + 1, str(result)[:200])
            except Exception as exc:  # noqa: BLE001
                logger.exception("Iteration %d failed: %s", i + 1, exc)

    def run_interactive(self) -> None:
        """Run in interactive mode — prompts user for traffic scenario."""
        logger.info("Starting SwarmShield interactive mode")
        self._setup_bus_subscriptions()
        self._start_honeypot_bridge()
        if self._reporter:
            self._reporter.subscribe_to_bus()
        print("\n" + "=" * 60)
        print("  SwarmShield — Interactive Multi-Agent Defense Mode")
        print("=" * 60)
        print("Describe the network traffic scenario to analyse.")
        print("Examples:")
        print("  'DDoS flood from 10.0.0.5'")
        print("  'Port scan from 192.168.50.20'")
        print("  'Normal traffic monitoring'")
        if os.environ.get("HUMAN_APPROVAL", "false").lower() == "true":
            print("  [HUMAN APPROVAL MODE] You will be asked to confirm each defense action.")
        print("Type 'quit' to exit.\n")

        while True:
            try:
                user_input = input("Traffic scenario > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting interactive mode.")
                break

            if user_input.lower() in ("quit", "exit", "q"):
                print("Exiting.")
                break

            if not user_input:
                print("Please enter a scenario description.")
                continue

            try:
                if self._reporter:
                    self._reporter.print_banner(user_input)
                crew = self.build()
                result = crew.kickoff(inputs={"traffic_input": user_input})
                if self._reporter:
                    self._reporter.print_summary()
                print(f"\nResult:\n{result}\n")
            except Exception as exc:  # noqa: BLE001
                logger.exception("Interactive run failed: %s", exc)
                print(f"Error: {exc}\n")

    def run_batch(self, iterations: int = 1) -> None:
        """Run in batch mode with varied synthetic scenarios."""
        logger.info("Running SwarmShield batch mode (%d iteration(s))", iterations)
        self._setup_bus_subscriptions()
        self._start_honeypot_bridge()
        if self._reporter:
            self._reporter.subscribe_to_bus()
        import random
        scenarios = [
            "SYN-flood DDoS from 10.0.0.1",
            "Horizontal port scan from 10.0.0.2",
            "Data exfiltration attempt from 10.0.0.4",
            "Mixed DDoS and port scan from multiple sources",
            "Baseline normal traffic — no attacks",
        ]
        random.shuffle(scenarios)
        results = []
        for i in range(iterations):
            scenario = scenarios[i % len(scenarios)]
            logger.info("Batch iteration %d/%d — %s", i + 1, iterations, scenario)
            try:
                if self._reporter:
                    self._reporter.print_banner(scenario)
                crew = self.build()
                result = crew.kickoff(inputs={"traffic_input": scenario})
                if self._reporter:
                    self._reporter.print_summary()
                results.append({"iteration": i + 1, "scenario": scenario, "status": "ok"})
                logger.info("Batch iteration %d complete.", i + 1)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Batch iteration %d failed: %s", i + 1, exc)
                results.append({"iteration": i + 1, "scenario": scenario,
                                 "status": "error", "error": str(exc)})

        ok = sum(1 for r in results if r["status"] == "ok")
        logger.info("Batch complete: %d/%d iterations succeeded.", ok, iterations)
