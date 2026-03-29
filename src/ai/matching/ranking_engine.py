import json
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


# ── Pydantic Models ────────────────────────────────────────────────────────────

class FreelancerProfile(BaseModel):
    id: str
    name: str
    location: str = ""
    skills: List[str] = []
    rating: float = 0
    hourlyRate: float = 0
    completedProjects: int = 0
    bio: str = ""
    availability: bool = True
    specializations: List[str] = []


class MatchedFreelancer(FreelancerProfile):
    matchScore: int = 0
    matchReason: str = ""
    estimatedTotal: int = 0


# ── Ranking Engine ─────────────────────────────────────────────────────────────

class RankingEngine:
    def __init__(self, llm_service):
        self.llm = llm_service

    async def rank_with_llm(
        self,
        freelancers: List[FreelancerProfile],
        project: Dict[str, Any],
    ) -> List[MatchedFreelancer]:
        try:
            freelancer_list = "\n".join([
                f"""
{i + 1}. ID: {f.id}
   Name: {f.name}
   Skills: {', '.join(f.skills)}
   Rate: ${f.hourlyRate}/hr
   Location: {f.location}
"""
                for i, f in enumerate(freelancers)
            ])

            prompt = f"""
You are a technical hiring expert ranking freelancers for a project.

PROJECT:
- Type: {project.get('projectType')}
- Platform: {project.get('platform')}
- Features: {', '.join(project.get('features', []))}
- Budget: ${project.get('budgetMin')} - ${project.get('budgetMax')}
- Timeline: {project.get('timeline')}
- Required Skills: {', '.join(project.get('techPreferences', []))}
- Expertise Needed: {project.get('expertiseNeeded')}

FREELANCERS:
{freelancer_list}

Rank these freelancers from BEST to WORST for this project.
For each, give a score 0-100 and a brief reason.

RETURN STRICT JSON ONLY:
[
  {{
    "id": "freelancer_id",
    "matchScore": 85,
    "matchReason": "Perfect skill match for Flutter + Firebase project"
  }}
]"""

            raw = await self.llm.call([{"role": "user", "content": prompt}])
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            rankings: List[Dict[str, Any]] = json.loads(cleaned)

            # Map rankings back to freelancer profiles
            freelancer_map = {f.id: f for f in freelancers}
            ranked: List[MatchedFreelancer] = []

            for r in rankings:
                freelancer = freelancer_map.get(r["id"])
                if not freelancer:
                    continue
                ranked.append(MatchedFreelancer(
                    **freelancer.dict(),
                    matchScore=r["matchScore"],
                    matchReason=r["matchReason"],
                    estimatedTotal=round(freelancer.hourlyRate * 160) if freelancer.hourlyRate else 0,
                ))

            return ranked[:5]

        except Exception:
            print("❌ LLM ranking failed, using algorithmic fallback")
            return self._algorithmic_rank(freelancers, project)

    def _algorithmic_rank(
        self,
        freelancers: List[FreelancerProfile],
        project: Dict[str, Any],
    ) -> List[MatchedFreelancer]:
        results = [
            MatchedFreelancer(
                **f.dict(),
                matchScore=self._calculate_score(f, project),
                matchReason=self._build_reason(f, project),
                estimatedTotal=round(f.hourlyRate * 160) if f.hourlyRate else 0,
            )
            for f in freelancers
        ]
        results.sort(key=lambda x: x.matchScore, reverse=True)
        return results[:5]

    # Keep for backward compatibility
    def rank(
        self,
        freelancers: List[FreelancerProfile],
        project: Dict[str, Any],
    ) -> List[MatchedFreelancer]:
        return self._algorithmic_rank(freelancers, project)

    def _calculate_score(self, f: FreelancerProfile, project: Dict[str, Any]) -> int:
        """
        New Production Scoring Formula:
        score = (skill_match * 0.4) + (budget_fit * 0.2) + (rating * 0.2) + (experience * 0.2)
        """
        # 1. Skill Match (40%)
        skill_score = 0
        tech_prefs = project.get("techPreferences", [])
        if tech_prefs:
            matched = [s for s in tech_prefs if s.lower() in [x.lower() for x in f.skills]]
            skill_score = (len(matched) / len(tech_prefs)) * 100
        else:
            skill_score = 70  # default if no prefs
        
        # 2. Budget Fit (20%)
        budget_score = 0
        budget_max = project.get("budgetMax") or project.get("budget")
        if budget_max and f.hourlyRate:
            estimated_monthly = f.hourlyRate * 160
            if estimated_monthly <= budget_max:
                budget_score = 100
            elif estimated_monthly <= budget_max * 1.3:
                budget_score = 60
            else:
                budget_score = 20
        else:
            budget_score = 50

        # 3. Rating (20%)
        # Assuming rating is 0-5
        rating_score = (f.rating / 5) * 100 if f.rating else 0

        # 4. Experience (20%)
        # Using completedProjects as a proxy (cap at 50 for 100%)
        experience_score = min((f.completedProjects / 50) * 100, 100) if f.completedProjects else 20

        # Weighted Total
        total_score = (skill_score * 0.4) + (budget_score * 0.2) + (rating_score * 0.2) + (experience_score * 0.2)
        return round(total_score)

    def _build_reason(self, f: FreelancerProfile, project: Dict[str, Any]) -> str:
        reasons: List[str] = []
        tech_prefs = project.get("techPreferences", [])
        matched = [s for s in tech_prefs if s.lower() in [x.lower() for x in f.skills]]

        if matched:
            reasons.append(f"Expert in {', '.join(matched)}")
        
        if f.rating and f.rating >= 4.5:
            reasons.append("Top-rated professional")
        
        if f.completedProjects and f.completedProjects > 10:
            reasons.append(f"Proven track record ({f.completedProjects}+ projects)")

        budget_status = "Fits budget" if f.hourlyRate * 160 <= (project.get("budgetMax") or 999999) else "Premium candidate"
        reasons.append(budget_status)

        return " · ".join(reasons) or "Balanced match for requirements"