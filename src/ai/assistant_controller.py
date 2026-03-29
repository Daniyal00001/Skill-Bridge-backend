# ============================================================
# PATH: backend/ai/assistant_controller.py
# PURPOSE: Single public FastAPI endpoint — receives all messages
#          from frontend, passes to orchestrator, returns response.
# ============================================================

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from shared.agent_types import AgentOutput, FreelancerResponse
from orchestrator.ai_orchestrator import AiOrchestrator
from shared.llm_service import LLMService
from memory.session_service import SessionService
from conversation.conversation_service import ConversationService
from extraction.extraction_service import ExtractionService
from matching.matching_service import MatchingService
from negotiation.negotiation_service import NegotiationService
from contract.contract_service import ContractService
from shared.db import Database

router = APIRouter(prefix="/api/assistant", tags=["Assistant"])

# ── Dependency wiring (async initialization) ──────────────────
async def get_orchestrator() -> AiOrchestrator:
    # Initialize DB
    await Database.connect()
    db = await Database.get_db()
    
    llm = LLMService()
    session_svc = SessionService()
    conversation_svc = ConversationService(llm, session_svc)
    extraction_svc = ExtractionService(llm, session_svc, db)
    matching_svc = MatchingService(llm, session_svc, db)
    negotiation_svc = NegotiationService(llm, session_svc)
    contract_svc = ContractService(llm)

    return AiOrchestrator(
        session_service=session_svc,
        conversation_service=conversation_svc,
        extraction_service=extraction_svc,
        matching_service=matching_svc,
        negotiation_service=negotiation_svc,
        contract_service=contract_svc,
        llm_service=llm,
    )

# Global orchestrator instance (initialized on startup)
orchestrator: AiOrchestrator = None

@router.on_event("startup")
async def startup_event():
    global orchestrator
    orchestrator = await get_orchestrator()


# ── Request / Response models ─────────────────────────────────
class AssistantRequest(BaseModel):
    message: str
    sessionId: Optional[str] = None
    clientName: Optional[str] = "Client"
    freelancerResponses: Optional[List[FreelancerResponse]] = []
    selectedFreelancerId: Optional[str] = None


class AssistantResponse(BaseModel):
    success: bool
    sessionId: str
    stage: str
    reply: str
    project: Optional[Dict[str, Any]] = None
    matches: Optional[List[Dict[str, Any]]] = None
    negotiationSummary: Optional[List[Dict[str, Any]]] = None
    contractText: Optional[str] = None


# ── Route ─────────────────────────────────────────────────────
@router.post("/message", response_model=AssistantResponse)
async def handle_assistant_message(body: AssistantRequest):
    try:
        from shared.agent_types import AgentInput

        result: AgentOutput = await orchestrator.run(
            AgentInput(
                sessionId=body.sessionId or "",
                message=body.message,
                clientName=body.clientName or "Client",
                freelancerResponses=body.freelancerResponses or [],
                selectedFreelancerId=body.selectedFreelancerId,
            )
        )

        return AssistantResponse(
            success=True,
            sessionId=result.sessionId,
            stage=result.stage,
            reply=result.reply,
            project=result.project.dict() if result.project else None,
            matches=[m.dict() for m in result.matches] if result.matches else None,
            negotiationSummary=[r.dict() for r in result.negotiationSummary] if result.negotiationSummary else None,
            contractText=result.contractText,
        )

    except Exception as e:
        print(f"❌ Controller error: {e}")
        raise HTTPException(status_code=500, detail=str(e))