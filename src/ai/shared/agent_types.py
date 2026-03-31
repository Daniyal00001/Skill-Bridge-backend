# ============================================================
# PATH: backend/ai/shared/agent_types.py
# PURPOSE: All Pydantic models used across AI agent modules
# ============================================================

from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator

from shared.constants import (
    AgentStage, 
    ExpertiseLevel, 
    UserType, 
    UrgencyLevel, 
    BudgetSensitivity, 
    CommunicationStyle
)


# ── User Persona ──────────────────────────────────────────────
class UserPersona(BaseModel):
    expertiseLevel: ExpertiseLevel = ExpertiseLevel.BEGINNER
    userType: UserType = UserType.CONFUSED
    urgency: UrgencyLevel = UrgencyLevel.LOW
    budgetSensitivity: BudgetSensitivity = BudgetSensitivity.MEDIUM
    communicationStyle: CommunicationStyle = CommunicationStyle.FORMAL
    primaryGoal: str = ""

# ── LLM Message ───────────────────────────────────────────────
class LLMMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


# ── Project Requirements ──────────────────────────────────────
class ProjectRequirements(BaseModel):
    projectType: Optional[str] = None
    platform: Optional[str] = None
    features: List[str] = []
    budgetMin: Optional[float] = None
    budgetMax: Optional[float] = None
    timeline: Optional[str] = None
    techPreferences: List[str] = []
    expertiseNeeded: Optional[Literal["entry", "intermediate", "senior"]] = None
    additionalNotes: Optional[str] = None

    @field_validator("expertiseNeeded", mode="before")
    @classmethod
    def normalize_expertise(cls, v):
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in ["entry", "intermediate", "senior"]:
                return v_lower
        return v


# ── Freelancer Profile ────────────────────────────────────────
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


# ── Matched Freelancer ────────────────────────────────────────
class MatchedFreelancer(FreelancerProfile):
    matchScore: int = 0
    estimatedTotal: int = 0
    matchReason: str = ""


# ── Freelancer Response ───────────────────────────────────────
class FreelancerResponse(BaseModel):
    freelancerId: str
    freelancerName: str
    replyText: str
    proposedPrice: Optional[float] = None
    isAvailable: Optional[bool] = None


# ── Negotiation Result ────────────────────────────────────────
class NegotiationResult(BaseModel):
    freelancerId: str
    freelancerName: str
    status: Literal["ACCEPTED", "PENDING", "DECLINED", "COUNTERED", "NO_REPLY", "QUESTIONS"]
    finalPrice: Optional[float] = None
    aiReply: Optional[str] = None
    notes: str = ""

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v):
        if isinstance(v, str):
            v_upper = v.upper()
            if v_upper in ["ACCEPTED", "PENDING", "DECLINED", "COUNTERED", "NO_REPLY", "QUESTIONS"]:
                return v_upper
        return v


# ── Negotiation State ─────────────────────────────────────────
class NegotiationState(BaseModel):
    responses: List[FreelancerResponse] = []
    results: List[NegotiationResult] = []
    recommendedFreelancerId: Optional[str] = None
    round: int = 0


# ── Agent Session ─────────────────────────────────────────────
class AgentSession(BaseModel):
    sessionId: str
    clientId: Optional[str] = None
    clientName: Optional[str] = None
    stage: AgentStage = AgentStage.UNDERSTAND
    persona: Optional[UserPersona] = None
    history: List[LLMMessage] = []
    project: Optional[ProjectRequirements] = None
    matches: Optional[List[MatchedFreelancer]] = None
    negotiationState: Optional[NegotiationState] = None
    contractText: Optional[str] = None
    createdAt: str = ""
    updatedAt: str = ""


# ── Agent Input ───────────────────────────────────────────────
class AgentInput(BaseModel):
    sessionId: str
    message: str
    clientName: Optional[str] = "Client"
    freelancerResponses: Optional[List[FreelancerResponse]] = []
    selectedFreelancerId: Optional[str] = None


# ── Agent Output ──────────────────────────────────────────────
class AgentOutput(BaseModel):
    sessionId: str
    reply: str
    stage: AgentStage
    project: Optional[ProjectRequirements] = None
    matches: Optional[List[MatchedFreelancer]] = None
    negotiationSummary: Optional[List[NegotiationResult]] = None
    contractText: Optional[str] = None