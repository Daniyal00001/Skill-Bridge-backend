# ============================================================
# PATH: backend/ai/negotiation/negotiation_state.py
# PURPOSE: State management for the negotiation pipeline
# ============================================================

from enum import Enum
from typing import Any, Dict, List, Optional
from shared.constants import MAX_NEGOTIATION_ROUNDS


class NegotiationStatus(str, Enum):
    PENDING   = "PENDING"
    ACCEPTED  = "ACCEPTED"
    DECLINED  = "DECLINED"
    COUNTERED = "COUNTERED"
    NO_REPLY  = "NO_REPLY"
    QUESTIONS = "QUESTIONS"


class NegotiationResult:
    """Represents one freelancer's negotiation outcome."""

    def __init__(
        self,
        freelancerId: str,
        freelancerName: str = "Freelancer",
        status: NegotiationStatus = NegotiationStatus.PENDING,
        notes: str = "",
        aiReply: str = "",
        proposedPrice: Optional[float] = None,
        finalPrice: Optional[float] = None,
    ):
        self.freelancerId   = freelancerId
        self.freelancerName = freelancerName
        self.status         = status if isinstance(status, str) else status.value
        self.notes          = notes
        self.aiReply        = aiReply
        self.proposedPrice  = proposedPrice
        self.finalPrice     = finalPrice

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "NegotiationResult":
        return NegotiationResult(
            freelancerId=   d.get("freelancerId", ""),
            freelancerName= d.get("freelancerName", "Freelancer"),
            status=         NegotiationStatus(d.get("status", "PENDING")),
            notes=          d.get("notes", ""),
            aiReply=        d.get("aiReply", ""),
            proposedPrice=  d.get("proposedPrice"),
            finalPrice=     d.get("finalPrice"),
        )


class NegotiationState:
    """
    Tracks the full negotiation lifecycle:
    - round counter (capped at MAX_NEGOTIATION_ROUNDS)
    - roomId (the chat room used for this negotiation)
    - results list (one NegotiationResult per freelancer)
    """

    def __init__(
        self,
        round: int = 0,
        roomId: Optional[str] = None,
        results: Optional[List[NegotiationResult]] = None,
        max_rounds: int = MAX_NEGOTIATION_ROUNDS,
    ):
        self.round      = round
        self.roomId     = roomId
        self.results    = results or []
        self.max_rounds = max_rounds

    def next_round(self):
        self.round += 1

    def is_expired(self) -> bool:
        return self.round >= self.max_rounds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round":   self.round,
            "roomId":  self.roomId,
            "results": [r.to_dict() for r in self.results],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "NegotiationState":
        results = [
            NegotiationResult.from_dict(r) if isinstance(r, dict) else r
            for r in d.get("results", [])
        ]
        return NegotiationState(
            round=   d.get("round", 0),
            roomId=  d.get("roomId"),
            results= results,
        )