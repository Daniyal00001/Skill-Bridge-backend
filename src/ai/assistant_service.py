# ============================================================
# PATH: backend / ai / assistant_service.py
# PURPOSE: Standalone assistant — conversation + extraction in one call
# ============================================================

import json
import re
from typing import Any, Dict, List


class AssistantService:
    def __init__(self, llm_service):
        self.llm = llm_service

    async def run(self, message: str, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        prompt = f"""
You are an AI project consultant.

Your job is to:
1. Continue the conversation with the user.
2. Extract project information from the conversation.

Return STRICT JSON ONLY.

Format:
{{
  "reply": "assistant reply to continue conversation",
  "project": {{
    "projectType": "",
    "platform": "",
    "features": [],
    "budgetMin": null,
    "budgetMax": null,
    "timeline": ""
  }}
}}

Conversation history:
{json.dumps(history)}

User message:
{message}
"""

        raw = await self.llm.call([{"role": "user", "content": prompt}], task="conversation")
        cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()

        try:
            parsed = json.loads(cleaned)
            return {
                "reply": parsed.get("reply", ""),
                "project": parsed.get("project", {}),
            }
        except Exception:
            print("❌ JSON parse failed")
            print(cleaned)
            return {"reply": raw, "project": {}}