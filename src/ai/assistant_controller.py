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
from memory.persistent_memory_service import PersistentMemoryService
from shared.db import Database
from moderation.moderation_service import ModerationService

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
    memory_svc = PersistentMemoryService(db)

    return AiOrchestrator(
        session_service=session_svc,
        conversation_service=conversation_svc,
        extraction_service=extraction_svc,
        matching_service=matching_svc,
        negotiation_service=negotiation_svc,
        contract_service=contract_svc,
        memory_service=memory_svc,
        llm_service=llm,
    )

# Global orchestrator and moderation instances
orchestrator: AiOrchestrator = None
moderation_service: ModerationService = None

@router.on_event("startup")
async def startup_event():
    global orchestrator, moderation_service
    # Ensure DB is connected
    await Database.connect()
    
    llm = LLMService()
    moderation_service = ModerationService(llm)
    orchestrator = await get_orchestrator()


# ── Request / Response models ─────────────────────────────────
class AssistantRequest(BaseModel):
    message: str
    sessionId: Optional[str] = None
    clientName: Optional[str] = "Client"
    clientId: Optional[str] = None
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
    chatRoomId: Optional[str] = None
    memory: Optional[Dict[str, Any]] = None
    title: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None


# ── Feature: AI Moderation Engine ──────────────────────────────
class ModerationRequest(BaseModel):
    message: str
    contractStatus: Optional[str] = "NONE"
    violationCount: Optional[int] = 0

@router.post("/moderate")
async def moderate_message(body: ModerationRequest):
    """
    Analyzes a message for off-platform communication attempts.
    Returns: violation (bool), severity, sanitized_message, etc.
    """
    try:
        llm = LLMService()
        mod_svc = ModerationService(llm)
        result = await mod_svc.moderate(
            message=body.message,
            contract_status=body.contractStatus,
            user_violation_count=body.violationCount
        )
        return {
            "success": True,
            "result": result.dict()
        }
    except Exception as e:
        print(f"❌ Moderation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Route ─────────────────────────────────────────────────────
@router.post("/message", response_model=AssistantResponse)
async def handle_assistant_message(body: AssistantRequest):
    try:
        from shared.agent_types import AgentInput
        
        # 1. Moderation Check
        mod_result = await moderation_service.moderate(
            message=body.message,
            contract_status="NONE", # AI Assistant current context
            user_violation_count=0 # Defaulting for now
        )
        
        if mod_result.violation and mod_result.suggested_action in ["block", "warn"]:
            return AssistantResponse(
                success=False,
                reply="⚠️ Sharing personal contact information (emails, phone numbers, or external links) is not allowed on SkillBridge. Your message has been flagged for review.",
                stage="UNDERSTAND"
            )

        result: AgentOutput = await orchestrator.run(
            AgentInput(
                sessionId=body.sessionId or "",
                message=body.message,
                clientName=body.clientName or "Client",
                clientId=body.clientId,
                freelancerResponses=body.freelancerResponses or [],
                selectedFreelancerId=body.selectedFreelancerId,
            )
        )

        return AssistantResponse(
            success=True,
            **result.dict()
        )

    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"❌ Controller error:\n{error_msg}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Feature: Multi-Session Management (ChatGPT Style) ──────────
@router.get("/sessions")
async def list_sessions(clientId: str):
    """
    Returns all AI assistant chat sessions for a specific user.
    Used for the left sidebar "Chat History".
    """
    try:
        db = await Database.get_db()
        cursor = db.ai_sessions.find({"clientId": clientId}).sort("updatedAt", -1)
        sessions = await cursor.to_list(length=100)
        
        return {
            "success": True,
            "sessions": [{
                "sessionId": s["sessionId"],
                "title": s.get("title") or (s["history"][0]["content"][:30] + "..." if s.get("history") else "Untitled Chat"),
                "stage": s["stage"],
                "updatedAt": s["updatedAt"],
                "lastMessage": s["history"][-1]["content"] if s.get("history") else ""
            } for s in sessions]
        }
    except Exception as e:
        print(f"❌ list_sessions error: {e}")
        return {"success": False, "sessions": []}

@router.get("/session/{sessionId}", response_model=AssistantResponse)
async def get_session_details(sessionId: str):
    """
    Reloads a specific chat session by its ID.
    Used when clicking a past chat from the history sidebar.
    """
    try:
        session_svc = SessionService()
        session = await session_svc.get(sessionId)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
            
        return AssistantResponse(
            success=True,
            sessionId=session["sessionId"],
            stage=session["stage"],
            reply="Welcome back! I've loaded our conversation history.",
            project=session.get("project"),
            matches=session.get("matches"),
            negotiationSummary=session.get("negotiationState", {}).get("results"),
            contractText=session.get("contractText"),
            chatRoomId=session.get("chatRoomId"),
            memory=session.get("memory"),
            title=session.get("title", "Past Chat"),
            history=session.get("history")
        )
    except Exception as e:
        print(f"❌ get_session_details error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Session lookup by Chat Room ID (used by Node.js socket autopilot) ─────────
@router.get("/session-by-room/{room_id}")
async def get_session_by_room(room_id: str):
    """
    Looks up the AI session that is managing this chat room.
    Called by Node.js socket when a freelancer sends a message in an AI-managed room.
    Returns: sessionId, clientId, freelancerProfileId needed to trigger autopilot.
    """
    try:
        db = await Database.get_db()
        # Find the session where negotiationState.roomId == room_id
        session = await db.ai_sessions.find_one({
            "negotiationState.roomId": room_id
        })
        if not session:
            return {"sessionId": None, "clientId": None, "freelancerProfileId": None}

        negotiation_state = session.get("negotiationState") or {}
        results = negotiation_state.get("results") or []
        freelancer_profile_id = results[0].get("freelancerId") if results else None

        return {
            "sessionId": session.get("sessionId"),
            "clientId": session.get("clientId"),
            "freelancerProfileId": freelancer_profile_id,
        }
    except Exception as e:
        print(f"❌ session-by-room error: {e}")
        return {"sessionId": None, "clientId": None, "freelancerProfileId": None}

# ── Feature 1: Explicit Negotiation Reply Hook ────────────────
class NegotiationReply(BaseModel):
    chatRoomId: str
    freelancerId: str
    replyText: str
    sessionId: str

@router.post("/negotiation/reply")
async def handle_negotiation_reply(body: NegotiationReply):
    """
    Direct hook for real-time autopilot responses.
    """
    from shared.agent_types import AgentInput, FreelancerResponse
    
    result = await orchestrator.run(
        AgentInput(
            sessionId=body.sessionId,
            message=f"Freelancer reply in {body.chatRoomId}: {body.replyText}",
            freelancerResponses=[
                FreelancerResponse(
                    freelancerId=body.freelancerId,
                    replyText=body.replyText
                )
            ]
        )
    )
    return {
        "success": True,
        "reply": result.reply,
        "stage": result.stage
    }

# ── Feature 2: Public Sharing ─────────────────────────────────
@router.get("/share/{sessionId}")
async def get_shared_session(sessionId: str):
    """
    Returns public chat history for sharing.
    """
    try:
        session_svc = SessionService()
        session = await session_svc.get(sessionId)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
            
        return {
            "success": True,
            "title": session.get("title", "AI Project Consultation"),
            "history": session.get("history", []),
            "clientName": session.get("clientName", "Client"),
            "stage": session.get("stage")
        }
    except Exception as e:
        print(f"❌ share error: {e}")
        raise HTTPException(status_code=500, detail=str(e))