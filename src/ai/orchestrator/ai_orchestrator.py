# ============================================================
# PATH: backend/ai/orchestrator/ai_orchestrator.py
# PURPOSE: Main orchestrator — routes stages, coordinates services
# ============================================================

import json
import re
from typing import Any, Dict, List, Optional

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
        llm_service,
    ):
        self.session_service = session_service
        self.conversation_service = conversation_service
        self.extraction_service = extraction_service
        self.matching_service = matching_service
        self.negotiation_service = negotiation_service
        self.contract_service = contract_service
        self.llm = llm_service

    async def run(self, input: AgentInput) -> AgentOutput:
        session = await self.session_service.get_or_create(
            input.sessionId, input.clientName
        )
        print(f"\n🤖 Stage: {session['stage']} | Session: {session['sessionId']}")

        stage = session["stage"]

        if stage == AgentStage.UNDERSTAND:
            return await self._handle_understand(session, input.message)
        elif stage == AgentStage.ANALYZE:
            return await self._handle_analyze(session, input.message)
        elif stage in (AgentStage.MATCH, AgentStage.OUTREACH):
            return await self._handle_match(session, input.message, input.selectedFreelancerId)
        elif stage == AgentStage.NEGOTIATE:
            return await self._handle_negotiate(session, input.freelancerResponses or [])
        elif stage == AgentStage.CONTRACT:
            return await self._handle_contract(session)
        else:
            return AgentOutput(
                sessionId=session["sessionId"],
                stage=session["stage"],
                reply="Processing...",
            )

    # ── CONTRACT stage ────────────────────────────────────────
    async def _handle_contract(self, session: Dict[str, Any]) -> AgentOutput:
        negotiation_state = session.get("negotiationState") or {}
        results = negotiation_state.get("results") or []
        
        # Determine which freelancer to contract with
        accepted = next((r for r in results if r["status"] == "ACCEPTED"), None)
        if not accepted:
            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.NEGOTIATE,
                reply="No freelancer has accepted yet. Please finish negotiation first.",
            )

        # Find the full match profile
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
            reply="The contract is ready! You can review and finalize it below.",
            project=session.get("project"),
            matches=session.get("matches"),
            negotiationSummary=results,
            contractText=contract_text,
        )

    # ── UNDERSTAND stage ──────────────────────────────────────
    async def _handle_understand(self, session: Dict[str, Any], message: str) -> AgentOutput:
        reply = await self.conversation_service.handle(session, message)
        extraction = await self.extraction_service.extract(session)

        persona = session.get("persona") or {}
        expertise_level = persona.get("expertiseLevel") or ExpertiseLevel.BEGINNER
        
        # Dynamic MIN_ROUNDS based on Persona
        min_rounds = 2 # default
        user_type = persona.get("userType")
        urgency = persona.get("urgency")
        
        if urgency == "high" and expertise_level == ExpertiseLevel.ADVANCED:
            min_rounds = 1
        elif user_type == "confused" and expertise_level == ExpertiseLevel.BEGINNER:
            min_rounds = 4
        elif user_type == "business_owner":
            min_rounds = 2
        elif user_type == "experienced_client":
            min_rounds = 1
        else:
            min_rounds = {
                ExpertiseLevel.BEGINNER: 3,
                ExpertiseLevel.INTERMEDIATE: 2,
                ExpertiseLevel.ADVANCED: 1
            }.get(expertise_level, 2)

        conversation_round = len(session.get("history", [])) // 2
        min_rounds_met = conversation_round >= min_rounds

        print(f"👤 Persona: {user_type} | 💬 Round: {conversation_round} | MinRequired: {min_rounds}")
        print(f"📊 isComplete: {extraction.isComplete} | confidence: {extraction.confidence}")

        should_match = await self._should_trigger_match(
            session,
            message,
            reply,
            extraction.isComplete,
            extraction.confidence,
            min_rounds_met,
        )

        if should_match:
            print("✅ LLM decided: Triggering MATCH stage...")
            await self.session_service.update_stage(session["sessionId"], AgentStage.MATCH)

            updated_session = await self.session_service.get(session["sessionId"])
            match_session = {
                **updated_session,
                "project": {
                    **(updated_session.get("project") or {}),
                    **(extraction.project or {}),
                },
            }

            match_result = await self.matching_service.handle(match_session)
            matches = match_result["matches"]
            print(f"🎯 Matches found: {len(matches)}")

            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.MATCH,
                reply=match_result["reply"],
                project=extraction.project,
                matches=matches,
            )

        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.UNDERSTAND,
            reply=reply,
            project=extraction.project,
        )

    # ── LLM decides if matching should trigger ────────────────
    async def _should_trigger_match(
        self,
        session: Dict[str, Any],
        user_message: str,
        ai_reply: str,
        is_complete: bool,
        confidence: float,
        min_rounds_met: bool,
    ) -> bool:
        if not min_rounds_met:
            return False
        if is_complete and confidence >= 80:
            return True

        try:
            prompt = f"""
You are deciding whether to trigger freelancer matching for a client conversation.

EXTRACTED PROJECT DATA:
{json.dumps(session.get("project"), indent=2)}

LAST USER MESSAGE: "{user_message}"
LAST AI REPLY: "{ai_reply}"
IS COMPLETE: {is_complete}
CONFIDENCE: {confidence}%

Should we trigger freelancer matching now? Consider:
1. Do we have projectType, features, budget AND timeline?
2. Is the client ready to see freelancers?
3. Did the AI signal it has everything needed?
4. Did the user ask to find/show freelancers?

RETURN ONLY: true or false"""

            result = await self.llm.call([{"role": "user", "content": prompt}])
            decision = "true" in result.strip().lower()
            print(f"🤖 LLM match decision: {decision}")
            return decision

        except Exception:
            print("❌ LLM match decision failed, using extraction result")
            return is_complete and confidence >= 50

    # ── ANALYZE stage ─────────────────────────────────────────
    async def _handle_analyze(self, session: Dict[str, Any], message: str) -> AgentOutput:
        await self.session_service.update_stage(session["sessionId"], AgentStage.MATCH)
        result = await self.matching_service.handle({**session, "stage": AgentStage.MATCH})

        return AgentOutput(
            sessionId=session["sessionId"],
            stage=AgentStage.MATCH,
            reply=result["reply"],
            project=session.get("project"),
            matches=result["matches"],
        )

    # ── MATCH stage ───────────────────────────────────────────
    async def _handle_match(
        self,
        session: Dict[str, Any],
        message: str,
        selected_freelancer_id: Optional[str] = None,
    ) -> AgentOutput:
        wants_to_hire = bool(
            re.search(r"hire|want.*hire|let.*hire|go.*with|choose|select", message, re.IGNORECASE)
        )

        if wants_to_hire and session.get("matches"):
            print(f"🤝 Starting negotiation | Freelancer: {selected_freelancer_id or 'top match'}")
            await self.session_service.update_stage(session["sessionId"], AgentStage.NEGOTIATE)

            updated_session = await self.session_service.get(session["sessionId"])
            result = await self.negotiation_service.handle(
                updated_session, [], selected_freelancer_id
            )

            return AgentOutput(
                sessionId=session["sessionId"],
                stage=AgentStage.NEGOTIATE,
                reply=result["reply"],
                project=session.get("project"),
                matches=session.get("matches"),
                negotiationSummary=result["results"],
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
            stage=AgentStage.NEGOTIATE,
            reply=result["reply"],
            project=session.get("project"),
            matches=session.get("matches"),
            negotiationSummary=result["results"],
        )