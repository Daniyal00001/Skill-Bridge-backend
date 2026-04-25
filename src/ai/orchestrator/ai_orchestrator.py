# ============================================================
# PATH: backend/ai/orchestrator/ai_orchestrator.py
# PURPOSE: Main orchestrator — routes stages, coordinates services
# ============================================================

import json
import re
from typing import Any, Dict, List, Optional

from datetime import datetime
from shared.constants import AgentStage, ExpertiseLevel
from shared.agent_types import AgentInput, AgentOutput


# Dynamic MIN_ROUNDS logic moved to method


class AiOrchestrator:
    def __init__(
        self,
        session_service,
        conversation_service,
        extraction_service,
        matching_service,
        negotiation_service,
        contract_service,
        memory_service,
        llm_service,
    ):
        self.session_service = session_service
        self.conversation_service = conversation_service
        self.extraction_service = extraction_service
        self.matching_service = matching_service
        self.negotiation_service = negotiation_service
        self.contract_service = contract_service
        self.memory_service = memory_service
        self.llm = llm_service

    async def run(self, input: AgentInput) -> AgentOutput:
        session = await self.session_service.get_or_create(
            input.sessionId, input.clientName, input.clientId
        )
        
        # 🧠 LONG-TERM (30-DAY) PERSISTENT MEMORY
        memory = None
        if input.clientId:
            memory = await self.memory_service.get(input.clientId)
            if memory:
                session["persistentMemory"] = memory.dict()
                print(f"🧠 Persistent memory loaded for user: {input.clientId}")

        # 🧠 30-DAY SESSION MEMORY (Historical session summaries)
        if session.get("clientId"):
            recent_history = await self.session_service.get_recent_history(session["clientId"])
            # Format history for LLM context
            memory_summary = "\n".join([
                f"- {h.get('project', {}).get('projectType')}: {h.get('project', {}).get('budgetMax')}$"
                for h in recent_history if h.get("project")
            ])
            session["memoryContext"] = memory_summary

        print(f"\n🤖 Stage: {session['stage']} | Session: {session['sessionId']}")

        stage = session["stage"]

        if stage == AgentStage.UNDERSTAND:
            result = await self._handle_understand(session, input.message)
        elif stage == AgentStage.ANALYZE:
            result = await self._handle_analyze(session, input.message)
        elif stage in (AgentStage.MATCH, AgentStage.OUTREACH):
            result = await self._handle_match(session, input.message, input.selectedFreelancerId)
        elif stage == AgentStage.NEGOTIATE:
            result = await self._handle_negotiate(session, input.freelancerResponses or [])
        elif stage == AgentStage.CONTRACT:
            result = await self._handle_contract(session)
        else:
            result = AgentOutput(
                sessionId=session["sessionId"],
                stage=session["stage"],
                reply="Processing...",
            )

        # ── 6. PERSISTENT MEMORY UPDATE (Long-term) ───────────────────
        await self._post_process_memory(input.clientId, session, result)

        # ── 7. ENSURE OUTPUT HAS HISTORY AND TITLE ───────────────────
        # Ensure result has the current session state
        result.title = session.get("title", "New Chat")
        
        # Format history as LLMMessages
        from shared.agent_types import LLMMessage
        history_objs = []
        for m in session.get("history", []):
            history_objs.append(LLMMessage(role=m.get("role", "user"), content=m.get("content", "")))
        result.history = history_objs

        return result

    async def _post_process_memory(self, client_id: str, session: Dict[str, Any], result: AgentOutput):
        if not client_id:
            return

        new_data = {}
        
        # 1. Update budget preferences from project data
        if result.project:
            new_data["budgetRange"] = {
                "min": result.project.budgetMin or 0,
                "max": result.project.budgetMax or 0
            }
        
        # 2. Update expertise level detection
        history = session.get("history", [])
        if len(history) > 2:
            # We could do a more complex analysis, for now just placeholder for learning
            pass

        # 3. Track hired freelancers and project history
        if result.stage in (AgentStage.MATCH, AgentStage.DONE):
            # Extract a brief summary of the CURRENT project to remember for 30 days
            if result.project:
                summary = f"{result.project.projectType} on {result.project.platform} with budget ${result.project.budgetMax}"
                # Prevent duplicates (check if this project summary is already in pastProjects)
                if not any(p.get("summary") == summary for p in session.get("memory", {}).get("pastProjects", [])):
                    new_data["pastProject"] = {
                        "summary": summary,
                        "date": datetime.now().isoformat(),
                        "stage": str(result.stage)
                    }

            negotiation_state = session.get("negotiationState") or {}
            results = negotiation_state.get("results") or []
            accepted = next((r for r in results if r["status"] == "ACCEPTED"), None)
            if accepted:
                new_data["hiredFreelancer"] = accepted["freelancerId"]
        
        updated_memory = await self.memory_service.update_preferences(client_id, new_data)
        result.memory = updated_memory


    # ── CONTRACT stage ────────────────────────────────────────
    async def _handle_contract(self, session: Dict[str, Any]) -> AgentOutput:
        negotiation_state = session.get("negotiationState") or {}
        results = negotiation_state.get("results") or []
        
        accepted = next((r for r in results if r["status"] == "ACCEPTED"), None)
        if not accepted:
            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.NEGOTIATE,
                reply="No freelancer has accepted yet.",
            )

        matches = session.get("matches") or []
        target = next((m for m in matches if m["id"] == accepted["freelancerId"]), matches[0])

        contract_text = await self.contract_service.generate(
            session.get("project"),
            target,
            accepted.get("finalPrice")
        )

        await self.session_service.update_stage(session["sessionId"], AgentStage.DONE)
        
        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.DONE,
            reply="🤝 Deal closed! The contract is generated and ready for your signature in the dashboard.",
            project=session.get("project"),
            matches=session.get("matches"),
            negotiationSummary=results,
            contractText=contract_text,
            chatRoomId=negotiation_state.get("roomId")
        )

    # ── UNDERSTAND stage ──────────────────────────────────────
    async def _handle_understand(self, session: Dict[str, Any], message: str) -> AgentOutput:
        # 1. 🧠 EXTRACT FIRST: Pull data from the user message
        extraction = await self.extraction_service.extract(session)
        
        # Get latest project data
        updated_session = await self.session_service.get(session["sessionId"])
        project_data = updated_session.get("project") or {}

        # 2. 💬 CONVERSE SECOND: Use updated data to decide what to ask next
        reply = await self.conversation_service.handle(updated_session, message)

        # 🎯 DECISION: Should we trigger matching?
        persona = session.get("persona", {})
        expertise = persona.get("expertiseLevel", "INTERMEDIATE")
        
        # Requirement: BEGINNER (3), INTERMEDIATE (2), ADVANCED (1)
        min_rounds_map = {
            "BEGINNER": 3,
            "INTERMEDIATE": 2,
            "ADVANCED": 1
        }
        min_rounds = min_rounds_map.get(expertise, 2)
        
        # If we have memory context from a previous session, we can expedite by 1 round
        if session.get("memoryContext"):
            min_rounds = max(1, min_rounds - 1)

        conversation_round = len(updated_session.get("history", [])) // 2
        
        # Check intent and completeness
        should_match = await self._should_trigger_match(
            updated_session, message, reply, extraction.isComplete, extraction.confidence, 
            conversation_round >= min_rounds
        )

        if should_match:
            print("🚀 Intent/Completeness Met: TRIGGERING MATCH STAGE...")
            await self.session_service.update_stage(session["sessionId"], AgentStage.MATCH)
            
            match_result = await self.matching_service.handle(updated_session)
            
            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.MATCH,
                reply=match_result["reply"],
                project=project_data,
                matches=match_result["matches"],
            )

        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.UNDERSTAND,
            reply=reply,
            project=project_data,
        )

    async def _should_trigger_match(
        self, 
        session: Dict[str, Any], 
        user_message: str, 
        ai_reply: str, 
        is_complete: bool, 
        confidence: float, 
        min_rounds_met: bool
    ) -> bool:
        # Base safety: at least some rounds of discovery
        if not min_rounds_met: 
            return False
            
        # 🎯 PILLAR CHECK: Requirements, Budget, Tech Stack, Timeline
        project = session.get("project", {})
        has_reqs = bool(project.get("projectType") or project.get("features"))
        has_budget = bool(project.get("budgetMax") or project.get("budgetMin"))
        has_tech = bool(project.get("techPreferences"))
        has_timeline = bool(project.get("timeline"))

        pillars_met = has_reqs and has_budget and has_tech and has_timeline
        
        if not pillars_met and not is_complete:
            # We don't have enough info yet
            return False

        # 2. LLM Intent Detection: Did user explicitly ask for freelancers/matching?
        try:
            prompt = f"""
Analyze the user's intent to see if they want to move to freelancer matching now.

CURRENT PROJECT STATUS:
- Complete: {is_complete}
- Data Confidence: {confidence}% (Fields: {json.dumps(session.get("project"))})

LAST USER MESSAGE: "{user_message}"
LAST AI REPLY: "{ai_reply}"

DECIDE: Should we show freelancers matching results now?
Consider 'true' if:
1. The user explicitly asked to "show freelancers", "find someone", "let's hire", "matching", etc.
2. The user has provided all "Four Pillars" (What they want, Budget, Tech Stack, and Timeline).

IMPORTANT: Even if the user asks for matches, if we are missing any of the 4 Pillars (Requirements, Budget, Tech Stack, Timeline), return 'false' and explain we need those first.

RETURN ONLY: true OR false"""
            result = await self.llm.call([{"role": "user", "content": prompt}], task="intent")
            decision = "true" in result.strip().lower()
            
            # Final Pillar Guard
            if decision and not pillars_met:
                print("⚠️ LLM wanted to match, but 'Four Pillars' not met yet.")
                return False
                
            if decision: print("💡 LLM detected intent and pillars met.")
            return decision
        except:
            return pillars_met and is_complete and confidence >= 60

    # ── MATCH/HIRE stage ───────────────────────────────────────────
    async def _handle_match(
        self,
        session: Dict[str, Any],
        message: str,
        selected_freelancer_id: Optional[str] = None,
    ) -> AgentOutput:
        wants_to_hire = bool(
            re.search(r"hire|want.*hire|let.*hire|go.*with|choose|select|pick", message, re.IGNORECASE)
        )

        if wants_to_hire and session.get("matches"):
            await self.session_service.update_stage(session["sessionId"], AgentStage.NEGOTIATE)
            updated_session = await self.session_service.get(session["sessionId"])
            result = await self.negotiation_service.handle(
                updated_session, [], selected_freelancer_id
            )

            # Redirect info included in reply
            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.NEGOTIATE,
                reply=result["reply"],
                project=session.get("project"),
                matches=session.get("matches"),
                negotiationSummary=result["results"],
                chatRoomId=result.get("chatRoomId")
            )

        result = await self.matching_service.handle(session)
        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.MATCH,
            reply=result["reply"],
            project=session.get("project"),
            matches=result["matches"],
        )

    # ── NEGOTIATE stage ───────────────────────────────────────
    async def _handle_negotiate(
        self, session: Dict[str, Any], freelancer_responses: List[Any]
    ) -> AgentOutput:
        result = await self.negotiation_service.handle(session, freelancer_responses)

        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.NEGOTIATE if result.get("status") != "ACCEPTED" else AgentStage.CONTRACT,
            reply=result["reply"],
            project=session.get("project"),
            matches=session.get("matches"),
            negotiationSummary=result["results"],
            chatRoomId=session.get("negotiationState", {}).get("roomId")
        )

    async def _handle_analyze(self, session: Dict[str, Any], message: str) -> AgentOutput:
        return await self._handle_match(session, message)