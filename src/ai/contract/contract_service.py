# ============================================================
# PATH: backend/ai/contract/contract_service.py
# PURPOSE: Logic to generate final contract text using AI
# ============================================================

from typing import Any, Dict, Optional, Union


class ContractService:
    def __init__(self, llm_service):
        self.llm = llm_service

    def _get(self, obj, key, default="N/A"):
        """Safe accessor that works with both dicts and Pydantic models."""
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    async def generate(
        self,
        project: Union[Dict[str, Any], Any],
        freelancer: Union[Dict[str, Any], Any],
        final_price: Optional[float] = None
    ) -> str:
        # Safely extract fields from either dict or Pydantic model
        project_type = self._get(project, "projectType", "Software Project")
        features     = self._get(project, "features", [])
        timeline     = self._get(project, "timeline", "To be agreed")
        fr_name      = self._get(freelancer, "name", "Freelancer")
        fr_location  = self._get(freelancer, "location", "Remote")
        fr_total     = self._get(freelancer, "estimatedTotal", 0)

        features_str = ", ".join(features) if isinstance(features, list) else str(features)
        price        = final_price or fr_total or 0

        prompt = f"""
You are a legal and technical contract expert generating a standard freelance agreement on SkillBridge platform.

PROJECT:
- Title: {project_type}
- Features: {features_str}
- Timeline: {timeline}
- Final Agreed Price: ${price}

FREELANCER:
- Name: {fr_name}
- Location: {fr_location}
- Main Responsibilities: Expert delivery of project features using best practices.

CONTRACT STRUCTURE:
1. Parties Involved
2. Scope of Work (Features)
3. Payment Terms (Fixed Price: ${price})
4. Deadlines & Timeline ({timeline})
5. Intellectual Property
6. Termination

Write a professional, standard contract text based on these details.
"""

        result = await self.llm.call([
            {"role": "system", "content": "You are an expert contract writer."},
            {"role": "user", "content": prompt}
        ], task="contract")

        return result.strip()

