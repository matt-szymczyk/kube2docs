"""AI provider abstraction — all AI calls go through here."""

import json
import logging
import threading
from typing import Any, cast

import litellm
from litellm.exceptions import AuthenticationError, RateLimitError, Timeout

logger = logging.getLogger(__name__)

# Suppress litellm's noisy logging
litellm.suppress_debug_info = True
for _name in ("litellm", "LiteLLM", "litellm.utils", "litellm.main"):
    logging.getLogger(_name).setLevel(logging.WARNING)


class AIProvider:
    """Wrapper around litellm for all AI interactions.

    Tracks call count against a budget cap.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        api_base: str | None = None,
        max_calls: int = 500,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.calls_used = 0
        self.max_calls = max_calls
        self.timeout = timeout
        self._lock = threading.Lock()

    @property
    def budget_remaining(self) -> int:
        return max(0, self.max_calls - self.calls_used)

    @property
    def budget_exhausted(self) -> bool:
        return self.calls_used >= self.max_calls

    def _build_kwargs(self, messages: list[dict[str, str]], temperature: float) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "timeout": self.timeout,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        return kwargs

    def _parse_json(self, text: str) -> dict[str, Any] | list[Any] | None:
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
        try:
            return cast(dict[str, Any] | list[Any], json.loads(text))
        except json.JSONDecodeError:
            logger.warning("AI response was not valid JSON for model=%s", self.model)
            return None

    def _call_litellm(self, system: str, user: str, temperature: float) -> str | None:
        """Send a chat completion and return raw text.

        Returns None if the call fails or budget is exhausted.
        """
        with self._lock:
            if self.budget_exhausted:
                logger.warning("AI budget exhausted (%d/%d calls used)", self.calls_used, self.max_calls)
                return None

        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        try:
            response = litellm.completion(**self._build_kwargs(messages, temperature))
            with self._lock:
                self.calls_used += 1
            return cast(str, response.choices[0].message.content.strip())
        except AuthenticationError:
            logger.error("AI authentication failed for model=%s — check your API key", self.model)
            return None
        except RateLimitError:
            logger.warning("AI rate limit hit for model=%s", self.model)
            return None
        except Timeout:
            logger.warning("AI call timed out after %ds for model=%s", self.timeout, self.model)
            return None
        except Exception:
            logger.warning("AI call failed for model=%s", self.model, exc_info=True)
            return None

    def complete_json(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
    ) -> dict[str, Any] | list[Any] | None:
        """Send a chat completion and parse the response as JSON.

        Returns the parsed JSON, or None if the call fails or budget is
        exhausted.
        """
        text = self._call_litellm(system, user, temperature)
        return self._parse_json(text) if text is not None else None

    def complete_text(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
    ) -> str | None:
        """Send a chat completion and return raw text.

        Returns None if the call fails or budget is exhausted.
        """
        return self._call_litellm(system, user, temperature)

    def complete_json_multi(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.0,
    ) -> dict[str, Any] | list[Any] | None:
        """Send a multi-turn chat completion and parse the response as JSON.

        Takes a full message list (system, user, assistant, user, ...) for
        iterative conversation loops. Returns parsed JSON, or None on failure.
        """
        with self._lock:
            if self.budget_exhausted:
                logger.warning("AI budget exhausted (%d/%d calls used)", self.calls_used, self.max_calls)
                return None

        try:
            response = litellm.completion(**self._build_kwargs(messages, temperature))
            with self._lock:
                self.calls_used += 1
            text = cast(str, response.choices[0].message.content.strip())
        except AuthenticationError:
            logger.error("AI authentication failed for model=%s — check your API key", self.model)
            return None
        except RateLimitError:
            logger.warning("AI rate limit hit for model=%s", self.model)
            return None
        except Timeout:
            logger.warning("AI call timed out after %ds for model=%s", self.timeout, self.model)
            return None
        except Exception:
            logger.warning("AI call failed for model=%s", self.model, exc_info=True)
            return None

        return self._parse_json(text)
