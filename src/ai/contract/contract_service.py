# ============================================================
# PATH: backend/ai/contract/contract_service.py
# PURPOSE: Logic to generate final contract text using AI
# ============================================================

from typing import Any, Dict, Optional
from shared.agent_types import ProjectRequirements, MatchedFreelancer

class ContractService:
    def __init__(self, llm_service):
        self.llm = llm_service

    async def generate(
        self,
        project: ProjectRequirements,
        freelancer: MatchedFreelancer,
        final_price: Optional[float] = None
    ) -> str:
        prompt = f"""
You are a legal and technical contract expert generating a standard freelance agreement on SkillBridge platform.

PROJECT:
- Title: {project.projectType}
- Features: {', '.join(project.features)}
- Timeline: {project.timeline}
- Final Agreed Price: ${final_price or freelancer.estimatedTotal}

FREELANCER:
- Name: {freelancer.name}
- Location: {freelancer.location}
- Main Responsibilities: Expert delivery of project features using best practices.

CONTRACT STRUCTURE:
1. Parties Involved
2. Scope of Work (Features)
3. Payment Terms (Fixed Price: ${final_price or freelancer.estimatedTotal})
4. Deadlines & Timeline ({project.timeline})
5. Intellectual Property
6. Termination

Write a professional, standard contract text based on these details.
"""

        result = await self.llm.call([
            {"role": "system", "content": "You are an expert contract writer."},
            {"role": "user", "content": prompt}
        ], task="contract")

        return result.strip()
