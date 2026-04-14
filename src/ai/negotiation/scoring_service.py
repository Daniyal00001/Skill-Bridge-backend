# ============================================================
# PATH: backend/src/ai/negotiation/scoring_service.py
# PURPOSE: Evaluates freelancer quality in real-time
# ============================================================

from typing import Any, Dict
import json
import re

class ScoringService:
    def __init__(self, llm_service):
        self.llm = llm_service

    async def evaluate(self, session: Dict[str, Any], freelancer: Dict[str, Any], message: str) -> Dict[str, Any]:
        """
        Evaluates a freelancer based on their message and project match.
        """
        prompt = f"""
        You are an expert recruiter. Evaluate this freelancer based on their proposal message and the project requirements.

        PROJECT:
        {json.dumps(session.get("project"), indent=2)}

        FREELANCER PROFILE:
        {json.dumps(freelancer, indent=2)}

        FREELANCER MESSAGE:
        "{message}"

        Return evaluation in JSON:
        {{
          "score": 0-100,
          "communication": 1-10,
          "priceFit": 1-10,
          "skillMatch": 1-10,
          "summary": "Short explanation"
        }}
        """
        
        raw = await self.llm.call([{"role": "user", "content": prompt}], task="scoring")
        try:
            # Clean JSON from markdown if present
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(cleaned)
        except Exception:
            return {
                "score": 70,
                "communication": 7,
                "priceFit": 7,
                "skillMatch": 7,
                "summary": "Unable to parse AI evaluation."
            }
