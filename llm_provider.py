"""
Abstraction layer for LLM providers.

Supports:
- anthropic (Claude) — default
- deepseek (DeepSeek API, OpenAI-compatible)
- openai (OpenAI API)

Usage:
    provider = LLMProvider()                          # reads from env vars
    provider = LLMProvider(provider="anthropic", ...) # explicit config
    text = provider.chat_completion(system="...", user="...")
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

PROVIDER_DEFAULTS = {
    "anthropic": {
        "env_key": "ANTHROPIC_API_KEY",
        "model": "claude-sonnet-4-5-20250929",
        "base_url": None,
    },
    "deepseek": {
        "env_key": "DEEPSEEK_API_KEY",
        "model": "deepseek-chat",
        "base_url": "https://api.deepseek.com",
    },
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "model": "gpt-4o",
        "base_url": None,
    },
}


class LLMProvider:
    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.provider = provider or os.getenv("LLM_PROVIDER", "anthropic")
        defaults = PROVIDER_DEFAULTS.get(self.provider, PROVIDER_DEFAULTS["anthropic"])

        self.api_key = api_key or os.getenv(defaults["env_key"], "")
        self.model = model or os.getenv("LLM_MODEL", "") or defaults["model"]
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "") or defaults.get("base_url")

        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = self._init_client()
        return self._client

    def _init_client(self):
        if self.provider == "anthropic":
            from anthropic import Anthropic
            return Anthropic(api_key=self.api_key)
        else:
            from openai import OpenAI
            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            return OpenAI(**kwargs)

    def chat_completion(
        self,
        system: str,
        user: str,
        temperature: float = 0.6,
        max_tokens: int = 4096,
    ) -> Optional[str]:
        """Send a chat completion request and return the text response."""
        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    temperature=temperature,
                )
                if not response.content:
                    return None
                return response.content[0].text
            else:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=temperature,
                )
                if not response.choices:
                    return None
                return response.choices[0].message.content
        except Exception as e:
            logger.error(f"LLM completion error ({self.provider}/{self.model}): {e}")
            return None
