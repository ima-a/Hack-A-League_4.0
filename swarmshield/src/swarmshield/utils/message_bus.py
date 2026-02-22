"""
SwarmShield A2A Message Bus
============================
Thread-safe, in-process publish/subscribe bus for agent-to-agent (A2A)
communication.  No external broker required — everything runs inside the
same Python process during the demo.

Design
------
- **Global singleton**: any module calls ``get_bus()`` to get the shared
  instance.  Agents never need to pass a bus reference around.
- **Topics** (constants listed at the bottom): each topic has a well-known
  name string (e.g. ``TOPIC_SCOUT_TICK``).
- **Synchronous delivery**: ``publish()`` calls all subscribers immediately in
  the publishing thread.  Handlers should be fast; expensive work belongs in
  a daemon thread spun off inside the handler.
- **Non-blocking guarantee**: every ``publish()`` call is wrapped so that a
  misbehaving subscriber never crashes the publishing agent.
- **Test-safe**: ``reset_bus()`` replaces the singleton with a fresh instance
  so unit tests stay fully isolated.

Usage
-----
Subscribe (typically in live_demo.py or a crew runner)::

    from swarmshield.utils.message_bus import get_bus, TOPIC_RESPONDER_ACTION

    def on_action(msg):
        print(f"Responder acted: {msg['action']} on {msg['source_ip']}")

    get_bus().subscribe(TOPIC_RESPONDER_ACTION, on_action)

Publish (inside agents — already wired, you don't need to call this)::

    from swarmshield.utils.message_bus import get_bus, TOPIC_RESPONDER_ACTION
    get_bus().publish(TOPIC_RESPONDER_ACTION, {"source_ip": ip, "action": action})

Message schemas per topic
--------------------------
``scout.tick``
    buffer_size, early_warnings (list[str]), confirmed_threats (list[str]),
    per_ip (dict), tick_time (float, epoch seconds)

``scout.early_warning``
    ips (list[str]), per_ip (dict), tick_time (float, epoch seconds)

``analyzer.pre_assessment``
    preemptive_actions (list[dict]), total_early_warnings (int), timestamp (str),
    agent_id (str)

``analyzer.assessment``
    risk_level (str), risk_score (float), recommendations (list), timestamp (str),
    agent_id (str)

``responder.action``
    source_ip (str), action (str), requester (str), success (bool),
    timestamp (str), agent_id (str)

``mahoraga.evolved``
    best_fitness (float), best_thresholds (dict), confidence_threshold (float),
    outcomes_used (int), generations_run (int), timestamp (str)
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known topic names (import these instead of using raw strings)
# ---------------------------------------------------------------------------
TOPIC_SCOUT_TICK           = "scout.tick"
TOPIC_SCOUT_EARLY_WARNING  = "scout.early_warning"
TOPIC_ANALYZER_PREASSESS   = "analyzer.pre_assessment"
TOPIC_ANALYZER_ASSESSMENT  = "analyzer.assessment"
TOPIC_RESPONDER_ACTION     = "responder.action"
TOPIC_MAHORAGA_EVOLVED     = "mahoraga.evolved"

ALL_TOPICS = (
    TOPIC_SCOUT_TICK,
    TOPIC_SCOUT_EARLY_WARNING,
    TOPIC_ANALYZER_PREASSESS,
    TOPIC_ANALYZER_ASSESSMENT,
    TOPIC_RESPONDER_ACTION,
    TOPIC_MAHORAGA_EVOLVED,
)


# ---------------------------------------------------------------------------
# Core bus implementation
# ---------------------------------------------------------------------------

class MessageBus:
    """
    Thread-safe in-process pub/sub message bus.

    Multiple subscribers per topic are supported.
    Subscribers are called in registration order.
    A subscriber exception is logged but never propagated to the publisher.
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._message_count: int = 0

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def subscribe(self, topic: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        """
        Register *handler* to be called whenever *topic* is published.

        Parameters
        ----------
        topic   : str   Topic name (use the TOPIC_* constants).
        handler : callable  ``handler(message: dict) -> None``
        """
        with self._lock:
            self._subscribers[topic].append(handler)
        logger.debug("Bus: subscribed to '%s' (total=%d)", topic,
                     len(self._subscribers[topic]))

    def unsubscribe(self, topic: str, handler: Callable) -> bool:
        """
        Remove a previously registered handler.
        Returns True if the handler was found and removed.
        """
        with self._lock:
            try:
                self._subscribers[topic].remove(handler)
                return True
            except ValueError:
                return False

    def subscriber_count(self, topic: str) -> int:
        """Number of subscribers currently registered for *topic*."""
        with self._lock:
            return len(self._subscribers[topic])

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, topic: str, message: Dict[str, Any]) -> int:
        """
        Deliver *message* to all subscribers of *topic*.

        Always adds ``_topic`` and ``_published_at`` metadata keys to the
        message dict before delivery (copy — original dict is not mutated).

        Returns the number of subscribers notified.
        Exceptions raised by subscribers are caught and logged; they never
        propagate back to the publisher.
        """
        enriched = {
            **message,
            "_topic":        topic,
            "_published_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            handlers = list(self._subscribers[topic])  # snapshot
        self._message_count += 1

        notified = 0
        for handler in handlers:
            try:
                handler(enriched)
                notified += 1
            except Exception as exc:      # noqa: BLE001
                logger.error(
                    "Bus: subscriber %r raised on topic '%s': %s",
                    getattr(handler, "__name__", repr(handler)),
                    topic, exc,
                )
        if notified:
            logger.debug(
                "Bus: published '%s' → %d subscriber(s)  (msg#%d)",
                topic, notified, self._message_count,
            )
        return notified

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def message_count(self) -> int:
        """Total number of messages published since creation / last reset."""
        return self._message_count

    def topics(self) -> List[str]:
        """Topics that currently have at least one subscriber."""
        with self._lock:
            return [t for t, subs in self._subscribers.items() if subs]

    def __repr__(self) -> str:
        return (
            f"<MessageBus topics={self.topics()} "
            f"messages_sent={self._message_count}>"
        )


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_bus_lock    = threading.Lock()
_bus: Optional[MessageBus] = None


def get_bus() -> MessageBus:
    """
    Return the global shared MessageBus instance, creating it on first call.

    Thread-safe.  Safe to call from any agent, tool, or demo script.
    """
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:              # double-checked locking
                _bus = MessageBus()
                logger.debug("MessageBus singleton created.")
    return _bus


def reset_bus() -> MessageBus:
    """
    Replace the global singleton with a new empty bus and return it.

    **Only intended for use in tests.**  Calling this during a live demo
    will discard all subscriptions.
    """
    global _bus
    with _bus_lock:
        _bus = MessageBus()
    return _bus
