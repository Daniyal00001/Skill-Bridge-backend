# ============================================================
# PATH: backend/shared/llm_service.py
# PURPOSE: LLM service with task-based token limits
# ============================================================

import asyncio
import os
import random
from typing import List, Union

import httpx

from shared.constants import LLM_BASE_URL, LLM_MODEL

# ── Fallback chain ────────────────────────────────────────
FALLBACK_MODELS = [
    "llama-3.1-8b-instant",
    "gemma2-9b-it",
]

# ── Task-based token limits ───────────────────────────────
TASK_TOKEN_LIMITS = {
    "conversation": 1500,  # Multi-turn chat — needs room
    "extraction":   1200,  # JSON extraction — medium-large
    "matching":     1000,  # Freelancer ranking — medium
    "negotiation":  1000,  # Chat messages — short
    "outreach":      400,  # Outreach message — short
    "analysis":      800,  # JSON analysis — medium
    "scoring":       600,  # Evaluation JSON — medium
    "moderation":    500,  # Warn/block analysis — very short
    "contract":     2000,  # Legal contract text — long
    "cover_letter": 1200,  # Cover letter — medium-large
    "intent":        100,  # true/false decisions — minimal
    "persona":       300,  # Persona detection JSON — small
    "title":         100,  # Chat title — minimal
    "default":      1000,  # Safe fallback
}

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class LLMService:
    def __init__(self):
        self.api_key    = os.getenv("GROQ_API_KEY", "")
        self.base_url   = LLM_BASE_URL
        self.model      = LLM_MODEL
        self.max_retries = 4

    async def _request(
        self,
        client: httpx.AsyncClient,
        model: str,
        messages: List[dict],
        max_tokens: int,
        max_retries: int = 4,
    ) -> str:
        for attempt in range(1, max_retries + 1):
            try:
                response = await client.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model":      model,
                        "max_tokens": max_tokens,
                        "messages":   messages,
                    },
                )

                # ── Retryable status codes ────────────────────
                if response.status_code in RETRYABLE_STATUS_CODES:
                    retry_after = response.headers.get("retry-after")
                    wait = float(retry_after) if retry_after else min(2 ** attempt + random.uniform(0, 1), 30)
                    print(f"⏳ [{model}] HTTP {response.status_code} — retrying in {wait:.1f}s (attempt {attempt}/{max_retries})")
                    await asyncio.sleep(wait)
                    continue

                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]

            except httpx.HTTPStatusError as e:
                print(f"❌ [{model}] HTTP error: {e.response.status_code}")
                if attempt == max_retries:
                    raise
                await asyncio.sleep(2 ** attempt + random.uniform(0, 1))

            except httpx.TimeoutException:
                print(f"⏰ [{model}] Timeout (attempt {attempt}/{max_retries})")
                if attempt == max_retries:
                    raise
                await asyncio.sleep(2 ** attempt)

            except Exception as e:
                print(f"⚠️ [{model}] Unexpected error (attempt {attempt}): {e}")
                if attempt == max_retries:
                    raise
                await asyncio.sleep(2 ** attempt)

        raise RuntimeError(f"LLM request to {model} failed after {max_retries} retries")

    async def call(
        self,
        messages: Union[str, List[dict]],
        task: str = "default",          # 👈 NEW param
    ) -> str:
        # ── Pick token limit for this task ────────────────
        max_tokens = TASK_TOKEN_LIMITS.get(task, TASK_TOKEN_LIMITS["default"])

        # ── Normalize string → message list ───────────────
        if isinstance(messages, str):
            formatted = [{"role": "user", "content": messages}]
        else:
            formatted = [{"role": m["role"], "content": m["content"]} for m in messages]

        async with httpx.AsyncClient(timeout=60.0) as client:

            # ── Try primary model ──────────────────────────
            try:
                return await self._request(client, self.model, formatted, max_tokens, self.max_retries)
            except Exception as primary_err:
                print(f"⚠️ Primary model [{self.model}] failed: {primary_err}. Trying fallbacks...")

            # ── Fallback chain ─────────────────────────────
            for fallback_model in FALLBACK_MODELS:
                try:
                    print(f"🔄 Attempting fallback: {fallback_model}")
                    result = await self._request(client, fallback_model, formatted, max_tokens, max_retries=2)
                    print(f"✅ Fallback [{fallback_model}] succeeded")
                    return result
                except Exception as fb_err:
                    print(f"❌ Fallback [{fallback_model}] also failed: {fb_err}")

        raise RuntimeError(f"All LLM models failed (primary: {self.model}, fallbacks: {FALLBACK_MODELS})")