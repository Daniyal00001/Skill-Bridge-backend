import json
import re
from typing import Any, Dict, List, Optional, TypeVar

from pydantic import BaseModel

from extraction.extraction_prompt import build_extraction_prompt, build_extraction_check_prompt

# ── Pydantic Models ────────────────────────────────────────────────────────────

class ProjectRequirements(BaseModel):
    projectType: Optional[str] = None
    platform: Optional[str] = None
    features: List[str] = []
    budgetMin: Optional[float] = None
    budgetMax: Optional[float] = None
    timeline: Optional[str] = None
    techPreferences: List[str] = []
    expertiseNeeded: Optional[str] = None  # "entry" | "intermediate" | "senior"
    additionalNotes: Optional[str] = None


class ExtractionResult(BaseModel):
    project: Dict[str, Any]
    isComplete: bool
    missingFields: List[str]
    confidence: float


class CompletenessCheck(BaseModel):
    isComplete: bool
    missingFields: List[str]
    confidence: float


# ── Service ────────────────────────────────────────────────────────────────────

class ExtractionService:
    def __init__(self, llm_service, session_service, db):
        self.llm = llm_service
        self.session_service = session_service
        self.db = db  # SQLAlchemy async session or similar

    async def extract(self, session: Dict[str, Any]) -> ExtractionResult:
        # Fetch real skills from DB (MongoDB/Motor version)
        skill_names = []
        if self.db is not None:
            try:
                # Seek both APPROVED and PENDING for now
                cursor = self.db.skills.find({"status": {"$in": ["APPROVED", "PENDING"]}})
                skills = await cursor.to_list(length=300)
                skill_names = [s["name"] for s in skills]
            except Exception as e:
                print(f"⚠️ Extraction: DB skill fetch failed: {e}")

        project = await self._extract_project_data(session, skill_names)
        existing_project = session.get("project", {})
        
        # Smart merge: Only update if new data is non-null
        merged = {**existing_project}
        for k, v in project.items():
            if v is not None and v != [] and v != "":
                merged[k] = v
        
        session["project"] = merged
        await self.session_service.save(session)

        check = await self._check_completeness(session)

        print(f"📋 isComplete: {check.isComplete} | confidence: {check.confidence}%")
        print(f"📋 Extracted: {json.dumps(project, indent=2)}")

        return ExtractionResult(
            project=project,
            isComplete=check.isComplete,
            missingFields=check.missingFields,
            confidence=check.confidence,
        )

    async def _extract_project_data(
        self, session: Dict[str, Any], available_skills: List[str]
    ) -> Dict[str, Any]:
        prompt = build_extraction_prompt(session, available_skills)
        messages = [{"role": "user", "content": prompt}]
        raw = await self.llm.call(messages)

        fallback = ProjectRequirements().dict()
        return self._parse_json(raw, fallback)

    async def _check_completeness(self, session: Dict[str, Any]) -> CompletenessCheck:
        prompt = build_extraction_check_prompt(session)
        messages = [{"role": "user", "content": prompt}]
        raw = await self.llm.call(messages)

        fallback = {"isComplete": False, "missingFields": [], "confidence": 0}
        parsed = self._parse_json(raw, fallback)
        return CompletenessCheck(**parsed)

    def _parse_json(self, raw: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        try:
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(cleaned)
        except Exception:
            print(f"❌ ExtractionService JSON parse failed: {raw}")
            return fallback