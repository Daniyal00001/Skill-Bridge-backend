# ============================================================
# PATH: backend / ai / moderation / moderation_service.py
# PURPOSE: Service for AI-powered chat/message moderation
# ============================================================

import json
import re
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel

from moderation.moderation_prompt import build_moderation_prompt

class ModerationResult(BaseModel):
    violation: bool
    severity: Literal["low", "medium", "high"]
    confidence: int
    detected_patterns: List[str]
    detected_keywords: List[str]
    intent: Literal["none", "suspicious", "bypass_attempt"]
    reason: str
    suggested_action: Literal["allow", "warn", "block", "restrict"]
    sanitized_message: str
    risk_score_increment: int

class ModerationService:
    def __init__(self, llm_service):
        self.llm = llm_service

    async def moderate(self, message: str, contract_status: str = "NONE", user_violation_count: int = 0) -> ModerationResult:
        prompt = build_moderation_prompt(message, contract_status, user_violation_count)
        
        # Call LLM
        messages = [{"role": "system", "content": prompt}]
        raw = await self.llm.call(messages, task="moderation")
        
        # Parse JSON
        fallback = {
            "violation": False,
            "severity": "low",
            "confidence": 100,
            "detected_patterns": [],
            "detected_keywords": [],
            "intent": "none",
            "reason": "Fallback: Could not process moderation",
            "suggested_action": "allow",
            "sanitized_message": message,
            "risk_score_increment": 0
        }
        
        try:
            # Strip any markdown code blocks
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            # Also occasionally LLM adds text before/after JSON
            json_pattern = re.search(r"({.*})", cleaned, re.DOTALL)
            if json_pattern:
                cleaned = json_pattern.group(1)
            
            parsed = json.loads(cleaned)
            return ModerationResult(**parsed)
        except Exception as e:
            print(f"❌ ModerationService JSON parse failed: {e} | Raw: {raw}")
            return ModerationResult(**fallback)
