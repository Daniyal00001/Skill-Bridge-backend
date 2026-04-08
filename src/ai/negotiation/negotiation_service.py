# ============================================================
# PATH: backend/ai/negotiation/negotiation_service.py
# PURPOSE: Handles real-time outreach and negotiation in DB
# ============================================================

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from bson import ObjectId

from shared.constants import AgentStage
from shared.db import Database
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
        """
        Handles the negotiation flow. Now integrates with real DB.
        """
        db = await Database.get_db()
        matches: List[Dict[str, Any]] = session.get("matches") or []

        if not matches:
            return {
                "reply": "No freelancers to negotiate with.",
                "results": [],
            }

        negotiation_state = session.get("negotiationState") or {}
        current_round = negotiation_state.get("round", 0)

        # ── 1. Outreach (Starting the conversation) ──────────────────
        if not negotiation_state or current_round == 0:
            return await self._start_outreach(db, session, matches, selected_freelancer_id)

        # ── 2. Handle Responses (Autopilot) ───────────────────────────
        if freelancer_responses:
            return await self._handle_responses(db, session, freelancer_responses)

        return {
            "reply": "Waiting for freelancer response...",
            "results": negotiation_state.get("results", []),
        }

    async def _start_outreach(
        self,
        db,
        session: Dict[str, Any],
        matches: List[Dict[str, Any]],
        selected_freelancer_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a real ChatRoom and sends the first message.
        """
        if selected_freelancer_id:
            selected = next((m for m in matches if m["id"] == selected_freelancer_id), None)
            target = selected if selected else matches[0]
        else:
            target = matches[0]

        # 1. Create or Find ChatRoom in DB
        client_id = session.get("clientId")
        # Find clientProfileId from userId
        client_profile = await db.client_profiles.find_one({"userId": ObjectId(client_id)})
        if not client_profile:
             return {"reply": "Client profile not found. Please complete your profile.", "results": []}

        # freelancer_id in target is likely the freelancerProfileId
        freelancer_profile_id = target["id"]

        room = await db.chat_rooms.find_one({
            "clientProfileId": client_profile["_id"],
            "freelancerProfileId": ObjectId(freelancer_profile_id)
        })

        if not room:
            room_data = {
                "clientProfileId": client_profile["_id"],
                "freelancerProfileId": ObjectId(freelancer_profile_id),
                "projectId": ObjectId(session.get("project", {}).get("id")) if session.get("project", {}).get("id") else None,
                "isActiveAI": True,
                "createdAt": datetime.now(),
                "clientDeleted": False,
                "freelancerDeleted": False
            }
            res = await db.chat_rooms.insert_one(room_data)
            room_id = str(res.inserted_id)
        else:
            room_id = str(room["_id"])
            await db.chat_rooms.update_one({"_id": room["_id"]}, {"$set": {"isActiveAI": True}})

        # 2. Generate Outreach
        prompt = build_negotiation_outreach_prompt(session, target)
        message_content = await self.llm.call([{"role": "user", "content": prompt}])

        # 3. Save as Real Message
        msg_data = {
            "chatRoomId": ObjectId(room_id),
            "senderId": ObjectId(client_id), # Representing the client
            "content": message_content,
            "type": "TEXT",
            "isRead": False,
            "isAiMessage": True,
            "sentAt": datetime.now()
        }
        await db.messages.insert_one(msg_data)

        results = [{
            "freelancerId": freelancer_profile_id,
            "freelancerName": target["name"],
            "status": "PENDING",
            "notes": message_content,
        }]

        # Save session state
        updated_session = {
            **session,
            "stage": AgentStage.NEGOTIATE,
            "negotiationState": {
                "responses": [],
                "results": results,
                "round": 1,
                "roomId": room_id
            },
        }
        await self.session_service.save(updated_session)

        return {
            "reply": f"Outreach sent to **{target['name']}**! Redirecting you to chat...",
            "results": results,
            "chatRoomId": room_id
        }

    async def _handle_responses(
        self,
        db,
        session: Dict[str, Any],
        freelancer_responses: List[Any],
    ) -> Dict[str, Any]:
        """
        Handles real-time freelancer replies triggered by socket.
        """
        results: List[Dict[str, Any]] = []
        messages_to_db: List[Dict[str, Any]] = []

        for resp in freelancer_responses:
            freelancer_id = resp.freelancerId
            reply_text = resp.replyText
            room_id = session.get("negotiationState", {}).get("roomId")

            if not room_id: continue

            # 1. High-Precision Analysis via LLM
            analysis_prompt = build_negotiation_analysis_prompt(reply_text, session.get("project", {}).get("budgetMax", 0))
            analysis_raw = await self.llm.call([{"role": "user", "content": analysis_prompt}])
            analysis = self._parse_json(analysis_raw, {"status": "QUESTIONS", "proposedPrice": None})
            
            # 2. Logic-Driven Decision
            budget_max = session.get("project", {}).get("budgetMax", 0)
            proposed_price = analysis.get("proposedPrice")
            status = analysis.get("status")

            is_deal_confirmed = (status == "ACCEPTED") or self._detect_deal_close(reply_text)
            ai_reply = ""
            next_stage = AgentStage.NEGOTIATE

            # Logic: If price is mentioned, we apply the 10-20% rules
            if proposed_price:
                if proposed_price <= budget_max:
                    # Within budget -> Try to close or confirm
                    ai_reply = f"That sounds perfect. Your quote of ${proposed_price} works for the budget. Let's move forward with this!"
                    is_deal_confirmed = True
                elif proposed_price <= budget_max * 1.2:
                    # 10-20% over -> Counter convincingly
                    counter = budget_max
                    ai_reply = f"I appreciate the proposal. While ${proposed_price} is slightly above our target of ${budget_max}, we're prepared to move forward immediately at ${budget_max}. Given the well-defined scope and the potential for a long-term partnership with 5-star feedback, would this work for you?"
                    is_deal_confirmed = False
                else:
                    # > 20% over -> Polite decline/negotiate harder
                    ai_reply = f"Thank you for the quote. However, ${proposed_price} is significantly outside our established budget of ${budget_max}. We have a very clear project scope and are looking for a partner who can work within these constraints. Are you able to revise your quote, or should we explore other candidates?"
                    is_deal_confirmed = False
            else:
                # No price mentioned -> Standard AI reply
                if is_deal_confirmed:
                    ai_reply = "Great! I've confirmed our agreement. I'll prepare the contract for you now."
                else:
                    matches = session.get("matches") or []
                    freelancer = next((m for m in matches if m["id"] == freelancer_id), matches[0])
                    reply_prompt = build_negotiation_reply_prompt(session, freelancer, reply_text)
                    ai_reply = await self.llm.call([{"role": "user", "content": reply_prompt}])

            if is_deal_confirmed:
                next_stage = AgentStage.CONTRACT
                await db.chat_rooms.update_one({"_id": ObjectId(room_id)}, {"$set": {"isActiveAI": False}})

            # 3. Save AI Message to DB
            client_id = session.get("clientId")
            msg_data = {
                "chatRoomId": ObjectId(room_id),
                "senderId": ObjectId(client_id),
                "content": ai_reply,
                "type": "TEXT",
                "isRead": False,
                "isAiMessage": True,
                "sentAt": datetime.now()
            }
            await db.messages.insert_one(msg_data)
            
            results.append({
                "freelancerId": freelancer_id,
                "freelancerName": next((m["name"] for m in session.get("matches", []) if m["id"] == freelancer_id), "Freelancer"),
                "status": "ACCEPTED" if is_deal_confirmed else "PENDING",
                "aiReply": ai_reply,
                "proposedPrice": proposed_price
            })

        # Update session
        updated_session = {
            **session,
            "stage": next_stage,
            "negotiationState": {
                **session.get("negotiationState", {}),
                "round": session.get("negotiationState", {}).get("round", 1) + 1,
                "results": results
            }
        }
        await self.session_service.save(updated_session)

        return {"reply": results[0]["aiReply"], "results": results}

    def _detect_deal_close(self, text: str) -> bool:
        """
        Detects if the message indicates an agreement (Deal Closer Mode).
        """
        keywords = [r"\bok\b", r"\bgood\b", r"\bsounds good\b", r"\bagreed\b", r"\bfine\b", r"\blet's do\b", r"\bconfirm\b"]
        for kw in keywords:
            if re.search(kw, text, re.IGNORECASE):
                return True
        return False

    def _parse_json(self, raw: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        try:
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(cleaned)
        except Exception:
            return fallback