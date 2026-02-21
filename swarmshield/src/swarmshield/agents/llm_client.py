import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    _OPENAI_AVAILABLE = True
except ImportError:
    OpenAI = None           # type: ignore[assignment,misc]
    _OPENAI_AVAILABLE = False


class LLMClient:
    """
    Hallucination-resistant LLM client for SwarmShield agents.

    Design principles
    -----------------
    - temperature = 0.0   : fully deterministic, no creative variation
    - JSON-mode enforced  : response_format=json_object, no prose
    - Grounded prompts    : agents feed only measured numerical data;
                            the model is told those values are ground truth
    - Graceful fallback   : if no API key or openai package is missing,
                            every method returns None without raising
    """

    def __init__(
        self,
        model:       str   = "gpt-4o",
        temperature: float = 0.0,
        max_tokens:  int   = 700,
        api_key:     Optional[str] = None,
    ) -> None:
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self._client: Optional[Any] = None

        key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
        if not key:
            logger.debug(
                "LLMClient: OPENAI_API_KEY not set — LLM enrichment disabled."
            )
            return

        if not _OPENAI_AVAILABLE:
            logger.warning(
                "LLMClient: 'openai' package not installed. "
                "Run: pip install 'openai>=1.0.0'"
            )
            return

        try:
            self._client = OpenAI(api_key=key)
            logger.info(
                "LLMClient ready (model=%s, temperature=%.1f, max_tokens=%d)",
                model, temperature, max_tokens,
            )
        except Exception as exc:
            logger.warning("LLMClient: failed to initialise OpenAI client: %s", exc)

    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """True only when a live client is initialised and ready."""
        return self._client is not None

    # ------------------------------------------------------------------

    def complete(
        self,
        system_prompt: str,
        user_message:  str,
    ) -> Optional[Dict[str, Any]]:
        """
        Call the LLM with a (system, user) message pair.

        - Requests JSON output (response_format = json_object).
        - Returns a parsed dict, or None on any failure.
        - Never raises — all errors are caught and logged as warnings.
        """
        if not self.available:
            return None

        try:
            resp = self._client.chat.completions.create(    # type: ignore[union-attr]
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ],
            )
            raw = (resp.choices[0].message.content or "").strip()
            if not raw:
                logger.warning("LLMClient: model returned an empty response.")
                return None
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("LLMClient: JSON decode error — %s", exc)
            return None
        except Exception as exc:
            logger.warning("LLMClient: API call failed — %s", exc)
            return None
