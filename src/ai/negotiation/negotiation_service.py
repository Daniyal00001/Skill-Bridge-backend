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
from negotiation.negotiation_state import (
    NegotiationState,
    NegotiationStatus,
    NegotiationResult,
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
        db = await Database.get_db()
        matches: List[Dict[str, Any]] = session.get("matches") or []

        if not matches:
            return {"reply": "No freelancers to negotiate with.", "results": []}

        # ── Load State ────────────────────────────────────────
        state = NegotiationState.from_dict(session.get("negotiationState") or {})

        # ── 1. Outreach ───────────────────────────────────────
        if state.round == 0:
            return await self._start_outreach(db, session, matches, state, selected_freelancer_id)

        # ── 2. Handle Responses ───────────────────────────────
        if freelancer_responses:
            return await self._handle_responses(db, session, freelancer_responses, state)

        return {
            "reply": "Waiting for freelancer response...",
            "results": [r.__dict__ for r in state.results],
        }

    # ─────────────────────────────────────────────────────────
    # OUTREACH
    # ─────────────────────────────────────────────────────────
    async def _start_outreach(
        self,
        db,
        session: Dict[str, Any],
        matches: List[Dict[str, Any]],
        state: NegotiationState,
        selected_freelancer_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        # Pick target freelancer
        if selected_freelancer_id:
            target = next((m for m in matches if m["id"] == selected_freelancer_id), matches[0])
        else:
            target = matches[0]

        # Find client profile
        client_id = session.get("clientId")
        client_profile = await db.client_profiles.find_one({"userId": ObjectId(client_id)})
        if not client_profile:
            return {"reply": "Client profile not found. Please complete your profile.", "results": []}

        freelancer_profile_id = target["id"]

        # Create or find ChatRoom
        room = await db.chat_rooms.find_one({
            "clientProfileId": client_profile["_id"],
            "freelancerProfileId": ObjectId(freelancer_profile_id),
        })

        if not room:
            room_data = {
                "clientProfileId":    client_profile["_id"],
                "freelancerProfileId": ObjectId(freelancer_profile_id),
                "projectId":          ObjectId(session.get("project", {}).get("id")) if session.get("project", {}).get("id") else None,
                "isActiveAI":         True,
                "createdAt":          datetime.now(),
                "clientDeleted":      False,
                "freelancerDeleted":  False,
            }
            res = await db.chat_rooms.insert_one(room_data)
            room_id = str(res.inserted_id)
        else:
            room_id = str(room["_id"])
            await db.chat_rooms.update_one({"_id": room["_id"]}, {"$set": {"isActiveAI": True}})

        # Generate outreach message
        prompt = build_negotiation_outreach_prompt(session, target)
        message_content = await self.llm.call([{"role": "user", "content": prompt}], task="outreach")

        # Save message to DB
        msg_res = await db.messages.insert_one({
            "chatRoomId": ObjectId(room_id),
            "senderId":   ObjectId(client_id),
            "content":    message_content,
            "type":       "TEXT",
            "isRead":     False,
            "isAiMessage": True,
            "sentAt":     datetime.now(),
        })
        message_id = str(msg_res.inserted_id)

        # Notify Node.js backend to broadcast via Socket.io
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                await client.post(
                    "http://localhost:5000/api/ai/assistant/broadcast-message",
                    json={"roomId": room_id, "messageId": message_id}
                )
        except Exception as e:
            print(f"⚠️ Failed to broadcast AI message: {e}")

        # Update state
        state.round  = 1
        state.roomId = room_id
        state.results = [
            NegotiationResult(
                freelancerId=   freelancer_profile_id,
                freelancerName= target["name"],
                status=         NegotiationStatus.PENDING,
                notes=          message_content,
            )
        ]

        # Save session
        updated_session = {
            **session,
            "stage":            AgentStage.NEGOTIATE,
            "negotiationState": state.to_dict(),
        }
        await self.session_service.save(updated_session)

        return {
            "reply":      f"Outreach sent to **{target['name']}**! Redirecting you to chat...",
            "results":    [r.__dict__ for r in state.results],
            "chatRoomId": room_id,
        }

    # ─────────────────────────────────────────────────────────
    # HANDLE RESPONSES
    # ─────────────────────────────────────────────────────────
    async def _handle_responses(
        self,
        db,
        session: Dict[str, Any],
        freelancer_responses: List[Any],
        state: NegotiationState,
    ) -> Dict[str, Any]:

        # Check round expiry
        if state.is_expired():
            return {
                "reply":   "Maximum negotiation rounds reached. Please check with your client for final approval.",
                "results": [r.__dict__ for r in state.results],
            }

        budget_max  = session.get("project", {}).get("budgetMax", 0)
        client_id   = session.get("clientId")
        next_stage  = AgentStage.NEGOTIATE
        results     = []

        for resp in freelancer_responses:
            freelancer_id = resp.freelancerId
            reply_text    = resp.replyText
            room_id       = state.roomId

            if not room_id:
                continue

            # 1. Analyze reply
            analysis_prompt = build_negotiation_analysis_prompt(reply_text, budget_max)
            analysis_raw    = await self.llm.call([{"role": "user", "content": analysis_prompt}], task="analysis")
            analysis        = self._parse_json(analysis_raw, {"status": "QUESTIONS", "proposedPrice": None})

            proposed_price    = analysis.get("proposedPrice")
            status            = analysis.get("status")
            is_deal_confirmed = (status == "ACCEPTED") or self._detect_deal_close(reply_text)
            ai_reply          = ""

            # 2. Price-based negotiation logic
            if proposed_price:
                if proposed_price <= budget_max:
                    ai_reply          = f"That sounds perfect. Your quote of ${proposed_price} works for the budget. Let's move forward!"
                    is_deal_confirmed = True

                elif proposed_price <= budget_max * 1.2:
                    ai_reply = (
                        f"I appreciate the proposal. While ${proposed_price} is slightly above our target of "
                        f"${budget_max}, we're prepared to move forward immediately at ${budget_max}. "
                        f"Given the well-defined scope and potential for a long-term partnership with 5-star "
                        f"feedback, would this work for you?"
                    )
                    is_deal_confirmed = False

                else:
                    ai_reply = (
                        f"Thank you for the quote. However, ${proposed_price} is significantly outside our "
                        f"budget of ${budget_max}. We have a very clear project scope — are you able to "
                        f"revise your quote, or should we explore other candidates?"
                    )
                    is_deal_confirmed = False

            else:
                # No price mentioned
                if is_deal_confirmed:
                    ai_reply = "Great! I've confirmed our agreement. I'll prepare the contract for you now."
                else:
                    matches    = session.get("matches") or []
                    freelancer = next((m for m in matches if m["id"] == freelancer_id), matches[0])

                    # Check if last round
                    if state.is_expired():
                        ai_reply = "I'll need to check with the client for final approval on this. I'll get back to you shortly."
                    else:
                        reply_prompt = build_negotiation_reply_prompt(session, freelancer, reply_text)
                        ai_reply     = await self.llm.call([{"role": "user", "content": reply_prompt}], task="negotiation")

            # 3. Handle deal close
            if is_deal_confirmed:
                next_stage = AgentStage.CONTRACT
                await db.chat_rooms.update_one(
                    {"_id": ObjectId(room_id)},
                    {"$set": {"isActiveAI": False}}
                )
                try:
                    await self._create_contract_in_db(db, session, freelancer_id, proposed_price or budget_max, room_id)
                except Exception as e:
                    print(f"❌ Failed to create contract: {e}")

            # 4. Save AI message to DB
            msg_res = await db.messages.insert_one({
                "chatRoomId":  ObjectId(room_id),
                "senderId":    ObjectId(client_id),
                "content":     ai_reply,
                "type":        "TEXT",
                "isRead":      False,
                "isAiMessage": True,
                "sentAt":      datetime.now(),
            })
            message_id = str(msg_res.inserted_id)

            # Notify Node.js backend to broadcast via Socket.io
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "http://localhost:5000/api/ai/assistant/broadcast-message",
                        json={"roomId": room_id, "messageId": message_id}
                    )
            except Exception as e:
                print(f"⚠️ Failed to broadcast AI message: {e}")

            # 5. Build result
            result = NegotiationResult(
                freelancerId=   freelancer_id,
                freelancerName= next((m["name"] for m in session.get("matches", []) if m["id"] == freelancer_id), "Freelancer"),
                status=         NegotiationStatus.ACCEPTED if is_deal_confirmed else NegotiationStatus(status or "PENDING"),
                aiReply=        ai_reply,
                proposedPrice=  proposed_price,
            )
            results.append(result)

        # ── Advance State ─────────────────────────────────────
        state.next_round()
        state.results = results

        updated_session = {
            **session,
            "stage":            next_stage,
            "negotiationState": state.to_dict(),
        }
        await self.session_service.save(updated_session)

        return {
            "reply":   results[0].aiReply if results else "",
            "results": [r.__dict__ for r in results],
        }

    # ─────────────────────────────────────────────────────────
    # CONTRACT CREATION
    # ─────────────────────────────────────────────────────────
    async def _create_contract_in_db(
        self,
        db,
        session: Dict[str, Any],
        freelancer_id: str,
        final_price: float,
        room_id: str,
    ):
        project_id = session.get("project", {}).get("id")
        if not project_id:
            return

        # Create contract
        contract_data = {
            "projectId":           ObjectId(project_id),
            "freelancerProfileId": ObjectId(freelancer_id),
            "agreedPrice":         float(final_price),
            "startDate":           datetime.now(),
            "status":              "OFFER_PENDING",
            "createdAt":           datetime.now(),
            "updatedAt":           datetime.now(),
        }

        existing = await db.contracts.find_one({"projectId": ObjectId(project_id)})
        if existing:
            contract_id = existing["_id"]
        else:
            res         = await db.contracts.insert_one(contract_data)
            contract_id = res.inserted_id

        # Create default milestone
        await db.milestones.insert_one({
            "contractId":  contract_id,
            "order":       0,
            "title":       "Initial Deliverable",
            "description": "Project kickoff and initial milestones as agreed in chat.",
            "amount":      float(final_price),
            "status":      "PENDING",
        })

        # Link contract to chat room
        await db.chat_rooms.update_one(
            {"_id": ObjectId(room_id)},
            {"$set": {"contractId": contract_id}}
        )

        # System notification message
        await db.messages.insert_one({
            "chatRoomId":  ObjectId(room_id),
            "senderId":    ObjectId(session.get("clientId")),
            "content":     f"🤝 **CONTRACT CREATED**\n\nA formal contract has been generated for ${final_price}. You can now view and manage milestones in the [Contract Detail Page](/contracts/{contract_id}).",
            "type":        "SYSTEM",
            "isRead":      False,
            "isAiMessage": True,
            "sentAt":      datetime.now(),
        })

        print(f"✅ Contract {contract_id} created for project {project_id}")

    # ─────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────
    def _detect_deal_close(self, text: str) -> bool:
        keywords = [r"\bok\b", r"\bgood\b", r"\bsounds good\b", r"\bagreed\b", r"\bfine\b", r"\blet's do\b", r"\bconfirm\b"]
        return any(re.search(kw, text, re.IGNORECASE) for kw in keywords)

    def _parse_json(self, raw: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        try:
            cleaned = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(cleaned)
        except Exception:
            return fallback