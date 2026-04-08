import asyncio
import os
from typing import List, Union

import httpx

from shared.constants import LLM_BASE_URL, LLM_MAX_TOKENS, LLM_MODEL


class LLMService:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.base_url = LLM_BASE_URL
        self.model = LLM_MODEL
        self.max_tokens = LLM_MAX_TOKENS
        self.max_retries = 3

    async def call(self, messages: Union[str, List[dict]]) -> str:
        # Normalize string → message list
        if isinstance(messages, str):
            formatted = [{"role": "user", "content": messages}]
        else:
            formatted = [
                {"role": m["role"], "content": m["content"]}
                for m in messages
            ]

        last_error: Exception = Exception("LLM request failed")

        async with httpx.AsyncClient(timeout=60.0) as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await client.post(
                        self.base_url,
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": self.model,
                            "max_tokens": self.max_tokens,
                            "messages": formatted,
                        },
                    )

                    # Rate limit handling
                    if response.status_code == 429:
                        wait = attempt * 2
                        print(f"⏳ Rate limited — retrying in {wait}s (attempt {attempt}/{self.max_retries})")
                        await asyncio.sleep(wait)
                        continue

                    response.raise_for_status()
                    data = response.json()
                    return data["choices"][0]["message"]["content"]

                except httpx.HTTPStatusError as e:
                    last_error = e
                    print(f"LLM HTTP error: {e.response.text}")
                    if attempt == self.max_retries:
                        raise RuntimeError("LLM request failed after retries") from e

                except Exception as e:
                    last_error = e
                    print(f"LLM Error (attempt {attempt}): {e}")
                    if attempt == self.max_retries:
                        break
                    await asyncio.sleep(attempt * 2)

        # Standard fallback for high availability
        print(f"⚠️ Primary model {self.model} failed. Attempting lightweight fallback (llama-3.1-8b-instant)...")
        try:
             async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "llama-3.1-8b-instant", # Lightweight reliable fallback
                        "max_tokens": 1024,
                        "messages": formatted,
                    },
                )
                response.raise_for_status()
                data = response.json()
                print("✅ Fallback successful")
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"❌ Fallback also failed: {e}")

        print(f"LLM Error after retries: {last_error}")
        raise RuntimeError("LLM request failed after retries")