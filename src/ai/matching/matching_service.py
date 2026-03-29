from typing import Any, Dict, List, Optional

from matching.ranking_engine import FreelancerProfile, MatchedFreelancer, RankingEngine

# ── Constants (mirrors AgentStage.MATCH) ──────────────────────────────────────
STAGE_MATCH = "MATCH"

AVAILABILITY_AVAILABLE = "AVAILABLE"

CATEGORY_MAP: Dict[str, str] = {
    "python": "AI & Machine Learning",
    "tensorflow": "AI & Machine Learning",
    "pytorch": "AI & Machine Learning",
    "machine learning": "AI & Machine Learning",
    "nlp": "AI & Machine Learning",
    "openai": "AI & Machine Learning",
    "langchain": "AI & Machine Learning",
    "react": "Web Development",
    "node": "Web Development",
    "nextjs": "Web Development",
    "vue": "Web Development",
    "angular": "Web Development",
    "flutter": "Mobile Development",
    "react native": "Mobile Development",
    "swift": "Mobile Development",
    "kotlin": "Mobile Development",
    "figma": "UI/UX Design",
    "adobe xd": "UI/UX Design",
    "solidity": "Blockchain & Web3",
    "ethereum": "Blockchain & Web3",
    "aws": "DevOps & Cloud",
    "docker": "DevOps & Cloud",
    "kubernetes": "DevOps & Cloud",
    "unity": "Game Development",
    "unreal": "Game Development",
}


# ── Service ────────────────────────────────────────────────────────────────────

class MatchingService:
    def __init__(self, llm_service, session_service, db):
        self.ranking_engine = RankingEngine(llm_service)
        self.session_service = session_service
        self.db = db  # async DB session

    async def handle(
        self, session: Dict[str, Any]
    ) -> Dict[str, Any]:
        project = session.get("project")
        if not project:
            return {"reply": "I need project details first.", "matches": []}

        tech_prefs = project.get("techPreferences") or []
        candidates = await self._query_freelancers(tech_prefs)

        if not candidates:
            return {
                "reply": "No freelancers found matching your requirements.",
                "matches": [],
            }

        # LLM-based ranking
        matches = await self.ranking_engine.rank_with_llm(candidates, project)

        # Save session with MATCH stage
        session["matches"] = [m.dict() for m in matches]
        session["stage"] = STAGE_MATCH
        await self.session_service.save(session)

        project_type = project.get("projectType")
        return {
            "reply": self._build_match_reply(matches, project_type),
            "matches": [m.dict() for m in matches],
        }

    async def _query_freelancers(
        self, required_skills: List[str]
    ) -> List[FreelancerProfile]:
        try:
            profiles = []

            # Step 1: Exact skill match
            profiles = await self._fetch_by_skills(required_skills, mode="exact")
            print(f"🔍 Exact skill match: {len(profiles)} found")

            # Step 2: Case-insensitive match
            if not profiles and required_skills:
                profiles = await self._fetch_by_skills(required_skills, mode="ilike")
                print(f"🔍 Case insensitive match: {len(profiles)} found")

            # Step 3: Category-based fallback
            if not profiles and required_skills:
                target_category = self._resolve_category(required_skills)
                print(f"🔍 Category fallback: {target_category}")
                profiles = await self._fetch_by_category(target_category)
                print(f"🔍 Category match: {len(profiles)} found")

            return profiles

        except Exception as e:
            print(f"❌ DB error: {e}")
            return []

    async def _fetch_by_skills(
        self, skills: List[str], mode: str = "exact"
    ) -> List[FreelancerProfile]:
        """
        Fetch freelancers by skill match.
        Replace query logic with your ORM (SQLAlchemy, Tortoise, etc.)
        `mode` is 'exact' or 'ilike'
        """
        # ── SQLAlchemy example (async) ─────────────────────────────
        # from sqlalchemy import select, func
        # stmt = (
        #     select(FreelancerProfileModel)
        #     .join(FreelancerSkill)
        #     .join(Skill)
        #     .where(FreelancerProfileModel.availability == AVAILABILITY_AVAILABLE)
        #     .where(
        #         Skill.name.in_(skills) if mode == "exact"
        #         else func.lower(Skill.name).in_([s.lower() for s in skills])
        #     )
        #     .limit(20)
        # )
        # rows = await self.db.execute(stmt)
        # return [self._map_profile(r) for r in rows.scalars()]
        # ──────────────────────────────────────────────────────────
    async def _fetch_by_skills(
        self, skills: List[str], mode: str = "exact"
    ) -> List[FreelancerProfile]:
        if self.db is None:
            return []
        
        try:
            # 1. First, find skill IDs for requested names
            skill_cursor = self.db.skills.find({"name": {"$in": skills}})
            found_skills = await skill_cursor.to_list(length=100)
            skill_ids = [s["_id"] for s in found_skills]
            
            if not skill_ids:
                return []

            # 2. Find freelancer profiles who HAVE these skills
            # (MongoDB Aggregation to join profile and skills)
            pipeline = [
                {"$lookup": {
                    "from": "freelancer_skills",
                    "localField": "_id",
                    "foreignField": "freelancerProfileId",
                    "as": "skill_links"
                }},
                {"$match": {
                    "skill_links.skillId": {"$in": skill_ids}
                    # Removed strict availability check for testing
                }},
                {"$limit": 20}
            ]
            
            cursor = self.db.freelancer_profiles.aggregate(pipeline)
            raw_profiles = await cursor.to_list(length=20)
            
            return [self._map_profile(r) for r in raw_profiles]
        except Exception as e:
            print(f"❌ Matching fetch failed: {e}")
            return []

    async def _fetch_by_category(self, category: str) -> List[FreelancerProfile]:
        if self.db is None:
            return []
        # Fallback category search logic
        try:
            pipeline = [
                {"$lookup": {
                    "from": "freelancer_skills",
                    "localField": "_id",
                    "foreignField": "freelancerProfileId",
                    "as": "skill_links"
                }},
                {"$lookup": {
                    "from": "skills",
                    "localField": "skill_links.skillId",
                    "foreignField": "_id",
                    "as": "skills_data"
                }},
                {"$match": {
                    "skills_data.category": category
                    # Removed strict availability check for testing
                }},
                {"$limit": 10}
            ]
            cursor = self.db.freelancer_profiles.aggregate(pipeline)
            raw_profiles = await cursor.to_list(length=10)
            return [self._map_profile(r) for r in raw_profiles]
        except Exception:
            return []

    def _map_profile(self, row: Any) -> FreelancerProfile:
        """Map ORM row to FreelancerProfile."""
        return FreelancerProfile(
            id=str(row["_id"]),
            name=row.get("fullName", "Unknown Freelancer"),
            location=row.get("location", ""),
            skills=[],  # Could populate this with another lookup if needed
            rating=4.5, # Placeholder rating
            hourlyRate=row.get("hourlyRate", 0.0),
            completedProjects=0,
            bio=row.get("bio", ""),
            availability=row.get("availability") == "AVAILABLE",
            specializations=row.get("preferredCategories", []),
        )

    def _build_match_reply(
        self, matches: List[MatchedFreelancer], project_type: Optional[str]
    ) -> str:
        names = "\n".join([
            f"{i + 1}. **{m.name}** — Score: {m.matchScore}/100 · {m.matchReason}"
            for i, m in enumerate(matches[:3])
        ])
        return (
            f"Found {len(matches)} freelancers for your {project_type or 'project'}!\n\n"
            f"{names}\n\n"
            f"Click \"Hire\" on any freelancer to start negotiation!"
        )