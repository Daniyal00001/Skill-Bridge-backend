# ============================================================
# PATH: backend/ai/negotiation/negotiation_service.py
# PURPOSE: Handles outreach and negotiation with freelancers
# ============================================================

import json
import re
from typing import Any, Dict, List, Optional

from shared.constants import AgentStage
from negotiation.negotiation_prompt import (
    build_negotiation_outreach_prompt,
    build_negotiation_reply_prompt,
    build_negotiation_analysis_prompt,
)


class NegotiationService:
    def __init__(self, llm_service, session_service):
        self.llm = llm_service
        self.session_service = session_service

    async def handle(
        self,
        session: Dict[str, Any],
        freelancer_responses: Optional[List[Any]] = None,
        selected_freelancer_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        freelancer_responses = freelancer_responses or []
        matches: List[Dict[str, Any]] = session.get("matches") or []

        if not matches:
            return {
                "reply": "No freelancers to negotiate with. Please go back to matching.",
                "results": [],
            }

        negotiation_state = session.get("negotiationState") or {}
        current_round = negotiation_state.get("round", 0)

        # First time — generate outreach
        if not negotiation_state or current_round == 0:
            return await self._start_outreach(session, matches, selected_freelancer_id)

        # Freelancer responses received
        if freelancer_responses:
            return await self._handle_responses(session, freelancer_responses)

        return {
            "reply": "Waiting for freelancer response...",
            "results": negotiation_state.get("results", []),
        }

    # ── Contact only the selected freelancer ──────────────────
    async def _start_outreach(
        self,
        session: Dict[str, Any],
        matches: List[Dict[str, Any]],
        selected_freelancer_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        if selected_freelancer_id:
            selected = next((m for m in matches if m["id"] == selected_freelancer_id), None)
            target_freelancers = [selected] if selected else [matches[0]]
        else:
            target_freelancers = [matches[0]]

        outreach_messages: List[str] = []
        results: List[Dict[str, Any]] = []

        for freelancer in target_freelancers:
            prompt = build_negotiation_outreach_prompt(session, freelancer)
            message = await self.llm.call([{"role": "user", "content": prompt}])

            outreach_messages.append(f"**To {freelancer['name']}:**\n{message}")
            results.append({
                "freelancerId": freelancer["id"],
                "freelancerName": freelancer["name"],
                "status": "PENDING",
                "notes": message,
            })

        # Save negotiation state
        updated_session = {
            **session,
            "stage": AgentStage.NEGOTIATE,
            "negotiationState": {
                "responses": [],
                "results": results,
                "round": 1,
            },
        }
        await self.session_service.save(updated_session)

        freelancer_name = target_freelancers[0]["name"]
        reply = (
            f"I've sent an outreach message to **{freelancer_name}** on your behalf!\n\n"
            f"{outreach_messages[0]}\n\n"
            f"I'll notify you as soon as they respond. You'll be redirected to the negotiation page now."
        )

        return {"reply": reply, "results": results}

    # ── Handle freelancer responses ───────────────────────────
    async def _handle_responses(
        self,
        session: Dict[str, Any],
        freelancer_responses: List[Any],
    ) -> Dict[str, Any]:

        matches: List[Dict[str, Any]] = session.get("matches") or []
        results: List[Dict[str, Any]] = []
        reply_messages: List[str] = []

        for resp in freelancer_responses:
            # Handle both Dict and Pydantic objects for robustness
            response = resp if isinstance(resp, dict) else (
                resp.model_dump() if hasattr(resp, "model_dump") else resp.dict()
            )

            freelancer = next(
                (m for m in matches if m["id"] == response["freelancerId"]), None
            )
            if not freelancer:
                continue

            budget_max = (session.get("project") or {}).get("budgetMax") or 0

            # Analyze reply using LLM
            analysis_prompt = build_negotiation_analysis_prompt(
                response["replyText"], budget_max
            )
            analysis_raw = await self.llm.call([{"role": "user", "content": analysis_prompt}])
            analysis = self._parse_json(analysis_raw, {
                "status": "PENDING",
                "proposedPrice": None,
                "isAvailable": True,
                "summary": "",
            })

            # Generate AI reply
            reply_prompt = build_negotiation_reply_prompt(
                session, freelancer, response["replyText"]
            )
            ai_reply = await self.llm.call([{"role": "user", "content": reply_prompt}])

            results.append({
                "freelancerId": freelancer["id"],
                "freelancerName": freelancer["name"],
                "status": analysis["status"],
                "finalPrice": analysis.get("proposedPrice"),
                "aiReply": ai_reply,
                "notes": analysis.get("summary", ""),
            })

            reply_messages.append(
                f"**{freelancer['name']}** ({analysis['status']}):\n{ai_reply}"
            )

        accepted = next((r for r in results if r["status"] == "ACCEPTED"), None)

        negotiation_state = session.get("negotiationState") or {}
        updated_session = {
            **session,
            "negotiationState": {
                "responses": freelancer_responses,
                "results": results,
                "recommendedFreelancerId": accepted["freelancerId"] if accepted else None,
                "round": (negotiation_state.get("round") or 1) + 1,
            },
        }
        await self.session_service.save(updated_session)

        reply = f"Negotiation Update:\n\n" + "\n\n---\n\n".join(reply_messages)

        if accepted:
            reply += f"\n\n✅ **{accepted['freelancerName']} has accepted!** Ready to generate the contract."
            await self.session_service.save({**session, "stage": AgentStage.CONTRACT})

        return {"reply": reply, "results": results}

    def _parse_json(self, raw: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        try:
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(cleaned)
        except Exception:
            return fallback