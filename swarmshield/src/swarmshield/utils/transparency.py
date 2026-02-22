"""
SwarmShield Transparency Reporter
===================================
Provides real-time visibility into every agent's thought process, tool calls,
and final outputs as the CrewAI crew executes.

Two integration points:
  1. **CrewAI callbacks** — wired via ``Crew(step_callback=..., task_callback=...)``
       • ``step_callback`` fires on every agent reasoning step (thought → tool → result)
       • ``task_callback`` fires when an entire task completes
  2. **A2A bus subscriptions** — receives cross-agent events from the message bus
       (Scout ticks, Analyzer assessments, Responder actions, Mahoraga evolution)

Output targets (configurable via env vars):
  TRANSPARENCY_CONSOLE=true   — pretty-printed, colour-coded terminal output (default)
  TRANSPARENCY_LOG=true       — writes JSON-Lines to ``transparency.log``
  TRANSPARENCY_LOG_FILE=path  — custom log file path (default: transparency.log)

Usage in crew.py::

    from swarmshield.utils.transparency import TransparencyReporter

    reporter = TransparencyReporter()
    crew = Crew(
        ...
        step_callback=reporter.on_agent_step,
        task_callback=reporter.on_task_complete,
    )
    reporter.subscribe_to_bus()   # also show A2A bus events
"""

from __future__ import annotations

import json
import logging
import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ANSI colour helpers (auto-disabled when stdout is not a TTY)
# ---------------------------------------------------------------------------

_COLOUR = sys.stdout.isatty()

_C = {
    "reset":    "\033[0m"   if _COLOUR else "",
    "bold":     "\033[1m"   if _COLOUR else "",
    "dim":      "\033[2m"   if _COLOUR else "",
    "cyan":     "\033[36m"  if _COLOUR else "",
    "green":    "\033[32m"  if _COLOUR else "",
    "yellow":   "\033[33m"  if _COLOUR else "",
    "red":      "\033[31m"  if _COLOUR else "",
    "magenta":  "\033[35m"  if _COLOUR else "",
    "blue":     "\033[34m"  if _COLOUR else "",
    "white":    "\033[97m"  if _COLOUR else "",
}

# One distinct colour per agent role
_AGENT_COLOURS = {
    "Network Traffic Scout":               _C["cyan"],
    "Threat Graph Analyzer":               _C["blue"],
    "Autonomous Defense Responder":        _C["red"],
    "Adaptive Threshold Evolver (Mahoraga)": _C["magenta"],
}

# A2A topic colours
_TOPIC_COLOURS = {
    "scout.tick":              _C["cyan"],
    "scout.early_warning":     _C["yellow"],
    "analyzer.pre_assessment": _C["blue"],
    "analyzer.assessment":     _C["blue"],
    "responder.action":        _C["red"],
    "mahoraga.evolved":        _C["magenta"],
}

_TOPIC_LABELS = {
    "scout.tick":              "SCOUT TICK",
    "scout.early_warning":     "EARLY WARNING",
    "analyzer.pre_assessment": "ANALYZER PRE-ASSESS",
    "analyzer.assessment":     "ANALYZER ASSESSMENT",
    "responder.action":        "RESPONDER ACTION",
    "mahoraga.evolved":        "MAHORAGA EVOLVED",
}

_WIDTH = 80


def _hr(char: str = "─", colour: str = "") -> str:
    return f"{colour}{char * _WIDTH}{_C['reset']}"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _wrap(text: str, indent: int = 4) -> str:
    prefix = " " * indent
    return textwrap.fill(str(text), width=_WIDTH - indent, initial_indent=prefix,
                         subsequent_indent=prefix)


# ---------------------------------------------------------------------------
# TransparencyReporter
# ---------------------------------------------------------------------------

class TransparencyReporter:
    """
    Hooks into the CrewAI execution pipeline to surface agent thought processes
    and cross-agent communications in real time.

    Wired via::

        reporter = TransparencyReporter()
        crew = Crew(
            step_callback=reporter.on_agent_step,
            task_callback=reporter.on_task_complete,
        )
        reporter.subscribe_to_bus()
    """

    def __init__(self) -> None:
        self._console: bool = (
            os.environ.get("TRANSPARENCY_CONSOLE", "true").lower() != "false"
        )
        self._log_enabled: bool = (
            os.environ.get("TRANSPARENCY_LOG", "true").lower() != "false"
        )
        self._log_file: str = os.environ.get(
            "TRANSPARENCY_LOG_FILE", "transparency.log"
        )
        self._step_count: int   = 0
        self._task_count: int   = 0
        self._current_agent: str = ""

    # ------------------------------------------------------------------
    # Internal output helpers
    # ------------------------------------------------------------------

    def _print(self, text: str) -> None:
        if self._console:
            print(text, flush=True)

    def _log(self, record: dict) -> None:
        if not self._log_enabled:
            return
        try:
            with open(self._log_file, "a") as fh:
                fh.write(json.dumps({**record, "_ts": _ts()}) + "\n")
        except OSError:
            pass

    def _agent_colour(self, role: str) -> str:
        for key, colour in _AGENT_COLOURS.items():
            if key.lower() in role.lower():
                return colour
        return _C["white"]

    # ------------------------------------------------------------------
    # step_callback — fires on every agent reasoning step
    # ------------------------------------------------------------------

    def on_agent_step(self, step: Any) -> None:
        """
        Called by CrewAI after every agent reasoning step.

        ``step`` is either:
          - ``AgentAction``  — has .thought, .tool, .tool_input, .result
          - ``AgentFinish``  — has .thought, .output   (or .return_values)
          - any other object — handled defensively
        """
        self._step_count += 1
        ts = _ts()

        # Extract fields defensively
        thought    = getattr(step, "thought",    None) or ""
        tool       = getattr(step, "tool",       None) or ""
        tool_input = getattr(step, "tool_input", None) or ""
        result     = getattr(step, "result",     None) or ""

        # AgentFinish has .output instead of .result
        if not result:
            rv = getattr(step, "return_values", None)
            if isinstance(rv, dict):
                result = rv.get("output", "")
            elif rv:
                result = str(rv)

        step_type = type(step).__name__   # AgentAction | AgentFinish | unknown

        # ---- console output -------------------------------------------
        if self._console:
            ac = self._agent_colour(self._current_agent)
            agent_label = f"{ac}{_C['bold']}{self._current_agent or 'Agent'}{_C['reset']}"
            step_label  = (
                f"{_C['yellow']}THOUGHT{_C['reset']}" if not tool
                else f"{_C['green']}TOOL CALL{_C['reset']}"
            )

            self._print(f"\n{_hr('-', _C['dim'])}")
            self._print(
                f" {_C['dim']}[{ts}] Step #{self._step_count} | "
                f"{agent_label}  {step_label}{_C['reset']}"
            )
            self._print(_hr("-", _C["dim"]))

            if thought:
                self._print(f"\n{_C['bold']}  Thought:{_C['reset']}")
                self._print(_wrap(thought))

            if tool:
                self._print(f"\n{_C['bold']}{_C['green']}  Tool:{_C['reset']} {tool}")
                if tool_input:
                    # Truncate long JSON inputs for readability
                    display_input = tool_input
                    if len(tool_input) > 400:
                        display_input = tool_input[:400] + "..."
                    self._print(f"{_C['dim']}")
                    self._print(_wrap(f"Input: {display_input}"))
                    self._print(f"{_C['reset']}", )

            if result:
                self._print(f"\n{_C['bold']}  Result:{_C['reset']}")
                display_result = str(result)
                if len(display_result) > 600:
                    display_result = display_result[:600] + "..."
                self._print(_wrap(display_result))

        # ---- log record -----------------------------------------------
        self._log({
            "event":      "agent_step",
            "step":       self._step_count,
            "step_type":  step_type,
            "agent":      self._current_agent,
            "thought":    thought[:500] if thought else "",
            "tool":       tool,
            "tool_input": tool_input[:500] if tool_input else "",
            "result":     str(result)[:500] if result else "",
        })

    # ------------------------------------------------------------------
    # task_callback — fires when a full task completes
    # ------------------------------------------------------------------

    def on_task_complete(self, task_output: Any) -> None:
        """
        Called by CrewAI when an entire task completes.

        ``task_output`` is a ``TaskOutput`` Pydantic model with:
          .agent, .description, .summary, .raw
        """
        self._task_count += 1
        ts = _ts()

        agent       = getattr(task_output, "agent",       None) or self._current_agent or "Agent"
        description = getattr(task_output, "description", None) or ""
        summary     = getattr(task_output, "summary",     None) or ""
        raw         = getattr(task_output, "raw",         None) or ""

        # Update current agent tracker
        if agent:
            self._current_agent = str(agent)

        # ---- console output -------------------------------------------
        if self._console:
            ac = self._agent_colour(str(agent))
            self._print(f"\n{_hr('=', ac)}")
            self._print(
                f" {_C['bold']}TASK {self._task_count} COMPLETE{_C['reset']}  "
                f"{ac}{_C['bold']}{agent}{_C['reset']}  "
                f"{_C['dim']}[{ts}]{_C['reset']}"
            )
            self._print(_hr("=", ac))

            if description:
                self._print(f"\n{_C['dim']}  Task:{_C['reset']} {description[:120]}")

            if summary:
                self._print(f"\n{_C['bold']}  Summary:{_C['reset']}")
                self._print(_wrap(summary))
            elif raw:
                self._print(f"\n{_C['bold']}  Output:{_C['reset']}")
                display = str(raw)[:800]
                if len(str(raw)) > 800:
                    display += "..."
                self._print(_wrap(display))

        # ---- log record -----------------------------------------------
        self._log({
            "event":       "task_complete",
            "task_num":    self._task_count,
            "agent":       str(agent),
            "description": str(description)[:200],
            "summary":     str(summary)[:500],
            "raw":         str(raw)[:1000],
        })

    # ------------------------------------------------------------------
    # Current-agent tracker
    # (CrewAI doesn't inject agent name into step_callback directly;
    # we track it via the A2A bus topic suffixes and task_callback)
    # ------------------------------------------------------------------

    def set_current_agent(self, role: str) -> None:
        self._current_agent = role

    # ------------------------------------------------------------------
    # A2A bus subscriptions — transparency for cross-agent events
    # ------------------------------------------------------------------

    def subscribe_to_bus(self) -> None:
        """
        Subscribe to all A2A message bus topics so that events produced by
        the underlying agents (and CrewAI tools) are surfaced in the
        transparency stream alongside the reasoning trace.
        """
        try:
            from .message_bus import (
                get_bus,
                TOPIC_SCOUT_TICK, TOPIC_SCOUT_EARLY_WARNING,
                TOPIC_ANALYZER_PREASSESS, TOPIC_ANALYZER_ASSESSMENT,
                TOPIC_RESPONDER_ACTION, TOPIC_MAHORAGA_EVOLVED,
            )
        except ImportError:
            logger.debug("message_bus unavailable — bus transparency disabled")
            return

        bus = get_bus()

        def _make_handler(topic: str):
            label  = _TOPIC_LABELS.get(topic, topic.upper())
            colour = _TOPIC_COLOURS.get(topic, _C["white"])

            def _handler(msg: dict) -> None:
                ts = _ts()
                # Build a concise human-readable summary per topic
                if topic == "scout.tick":
                    details = (
                        f"threats={len(msg.get('confirmed_threats', []))}  "
                        f"buffer={msg.get('buffer_size', '?')}"
                    )
                elif topic == "scout.early_warning":
                    details = f"suspicious IPs: {msg.get('ips', [])}"
                elif topic in ("analyzer.pre_assessment", "analyzer.assessment"):
                    details = (
                        f"risk={msg.get('risk_level', '?')}  "
                        f"score={msg.get('risk_score', '?')}"
                    )
                elif topic == "responder.action":
                    details = (
                        f"action={msg.get('action', '?')}  "
                        f"ip={msg.get('source_ip', '?')}  "
                        f"success={msg.get('success', '?')}"
                    )
                elif topic == "mahoraga.evolved":
                    details = (
                        f"fitness={msg.get('best_fitness', '?')}  "
                        f"generations={msg.get('generations_run', '?')}"
                    )
                else:
                    details = json.dumps({k: v for k, v in msg.items()
                                          if not k.startswith("_")})[:120]

                if self._console:
                    self._print(
                        f"\n  {colour}{_C['bold']}[A2A] {label}{_C['reset']}"
                        f"  {_C['dim']}[{ts}]{_C['reset']}"
                        f"\n  {_C['dim']}{details}{_C['reset']}"
                    )

                self._log({
                    "event":   "a2a_message",
                    "topic":   topic,
                    "details": details,
                    "payload": {k: v for k, v in msg.items() if not k.startswith("_")},
                })

            return _handler

        for topic in (
            TOPIC_SCOUT_TICK, TOPIC_SCOUT_EARLY_WARNING,
            TOPIC_ANALYZER_PREASSESS, TOPIC_ANALYZER_ASSESSMENT,
            TOPIC_RESPONDER_ACTION, TOPIC_MAHORAGA_EVOLVED,
        ):
            bus.subscribe(topic, _make_handler(topic))

        logger.debug("TransparencyReporter subscribed to all 6 A2A topics")

    # ------------------------------------------------------------------
    # Banner helpers — print when a run starts/ends
    # ------------------------------------------------------------------

    def print_banner(self, scenario: str = "") -> None:
        if not self._console:
            return
        self._print(f"\n{_hr('=', _C['cyan'])}")
        self._print(
            f" {_C['cyan']}{_C['bold']}SwarmShield - Agent Transparency Mode{_C['reset']}"
        )
        if scenario:
            self._print(f" {_C['dim']}Scenario: {scenario}{_C['reset']}")
        self._print(
            f" {_C['dim']}Log: {self._log_file}  "
            f"Console: {'on' if self._console else 'off'}  "
            f"Bus: subscribed{_C['reset']}"
        )
        self._print(_hr("=", _C["cyan"]))

    def print_summary(self) -> None:
        if not self._console:
            return
        self._print(f"\n{_hr('=', _C['green'])}")
        self._print(
            f" {_C['green']}{_C['bold']}Run Complete{_C['reset']}  "
            f"steps={self._step_count}  tasks={self._task_count}"
        )
        self._print(_hr("=", _C["green"]))
