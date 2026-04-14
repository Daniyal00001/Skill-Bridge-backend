# ============================================================
# PATH: backend/ai/moderation/blocking_service.py
# PURPOSE: Handles warn/block logic with DB persistence
# ============================================================

from datetime import datetime
from typing import Any, Dict, Optional
from bson import ObjectId

from moderation.moderation_service import ModerationService, ModerationResult


class BlockingService:
    def __init__(self, llm_service):
        self.moderation = ModerationService(llm_service)

    async def check_message(
        self,
        db,
        message: str,
        sender_id: str,
        room_id: str,
        contract_status: str = "NONE",
    ) -> Dict[str, Any]:
        """
        Main entry point. Call this before saving any chat message.
        Returns a decision dict the socket/controller should act on.
        """

        # 1. Load or create user moderation profile
        profile = await self._get_or_create_profile(db, sender_id)
        violation_count = profile.get("violationCount", 0)

        # 2. Check if already hard-blocked
        if profile.get("isBlocked"):
            return self._response(
                action="block",
                message="⛔ You are blocked from sending messages due to repeated policy violations.",
                result=None,
                profile=profile,
            )

        # 3. Run AI moderation
        result: ModerationResult = await self.moderation.moderate(
            message=message,
            contract_status=contract_status,
            user_violation_count=violation_count,
        )

        # 4. Allow — no violation
        if not result.violation or result.suggested_action == "allow":
            return self._response(
                action="allow",
                message=message,
                result=result,
                profile=profile,
            )

        # 5. Violation detected — process it
        return await self._handle_violation(db, sender_id, room_id, message, result, profile)

    # ─────────────────────────────────────────────────────────
    # VIOLATION HANDLER
    # ─────────────────────────────────────────────────────────
    async def _handle_violation(
        self,
        db,
        sender_id: str,
        room_id: str,
        message: str,
        result: ModerationResult,
        profile: Dict[str, Any],
    ) -> Dict[str, Any]:

        violation_count = profile.get("violationCount", 0)
        action          = result.suggested_action  # "warn" or "block"

        # Log violation to DB
        await self._log_violation(db, sender_id, room_id, message, result)

        # First violation → always warn, never hard block immediately
        if violation_count == 0:
            await self._update_profile(db, sender_id, increment_violation=True, block=False)
            warning_msg = self._build_warning_message(result, is_final=False)

            # Send system warning into the chat room
            await self._send_system_message(db, room_id, sender_id, warning_msg)

            return self._response(
                action="warn",
                message=warning_msg,
                result=result,
                profile=profile,
                sanitized_message=result.sanitized_message,
            )

        # Second+ violation → hard block
        else:
            await self._update_profile(db, sender_id, increment_violation=True, block=True)
            block_msg = self._build_block_message(result)

            # Send system block notice into chat room
            await self._send_system_message(db, room_id, sender_id, block_msg)

            # Disable chat room for this user
            await db.chat_rooms.update_one(
                {"_id": ObjectId(room_id)},
                {"$set": {"isBlocked": True, "blockedUserId": ObjectId(sender_id)}}
            )

            return self._response(
                action="block",
                message=block_msg,
                result=result,
                profile=profile,
            )

    # ─────────────────────────────────────────────────────────
    # DB HELPERS
    # ─────────────────────────────────────────────────────────
    async def _get_or_create_profile(self, db, sender_id: str) -> Dict[str, Any]:
        profile = await db.moderation_profiles.find_one({"userId": ObjectId(sender_id)})
        if not profile:
            new_profile = {
                "userId":         ObjectId(sender_id),
                "violationCount": 0,
                "riskScore":      0,
                "isBlocked":      False,
                "warnings":       [],
                "createdAt":      datetime.now(),
                "updatedAt":      datetime.now(),
            }
            await db.moderation_profiles.insert_one(new_profile)
            return new_profile
        return profile

    async def _update_profile(
        self,
        db,
        sender_id: str,
        increment_violation: bool = False,
        block: bool = False,
    ):
        update = {
            "$set": {
                "isBlocked": block,
                "updatedAt": datetime.now(),
            }
        }
        if increment_violation:
            update["$inc"] = {"violationCount": 1}

        await db.moderation_profiles.update_one(
            {"userId": ObjectId(sender_id)},
            update,
            upsert=True,
        )

    async def _log_violation(
        self,
        db,
        sender_id: str,
        room_id: str,
        message: str,
        result: ModerationResult,
    ):
        log = {
            "userId":            ObjectId(sender_id),
            "chatRoomId":        ObjectId(room_id),
            "originalMessage":   message,
            "sanitizedMessage":  result.sanitized_message,
            "severity":          result.severity,
            "intent":            result.intent,
            "detectedPatterns":  result.detected_patterns,
            "detectedKeywords":  result.detected_keywords,
            "suggestedAction":   result.suggested_action,
            "confidence":        result.confidence,
            "reason":            result.reason,
            "riskScoreIncrease": result.risk_score_increment,
            "createdAt":         datetime.now(),
        }
        await db.moderation_logs.insert_one(log)

    async def _send_system_message(
        self,
        db,
        room_id: str,
        sender_id: str,
        content: str,
    ):
        await db.messages.insert_one({
            "chatRoomId":  ObjectId(room_id),
            "senderId":    ObjectId(sender_id),
            "content":     content,
            "type":        "SYSTEM",
            "isRead":      False,
            "isAiMessage": True,
            "sentAt":      datetime.now(),
        })

    # ─────────────────────────────────────────────────────────
    # MESSAGE BUILDERS
    # ─────────────────────────────────────────────────────────
    def _build_warning_message(self, result: ModerationResult, is_final: bool) -> str:
        patterns = ", ".join(result.detected_patterns) if result.detected_patterns else ""
        keywords = ", ".join(result.detected_keywords) if result.detected_keywords else ""
        detected = " | ".join(filter(None, [patterns, keywords]))

        return (
            f"⚠️ **Policy Warning**\n\n"
            f"Your message contains content that violates platform guidelines.\n"
            f"**Reason:** {result.reason}\n"
            f"{'**Detected:** ' + detected + chr(10) if detected else ''}"
            f"\n🚫 Sharing personal contact info or moving off-platform is not allowed "
            f"before a contract is established.\n\n"
            f"❗ **This is your first warning. A second violation will result in an immediate block.**"
        )

    def _build_block_message(self, result: ModerationResult) -> str:
        return (
            f"⛔ **You Have Been Blocked**\n\n"
            f"You have been blocked from sending messages in this chat due to repeated "
            f"policy violations.\n"
            f"**Reason:** {result.reason}\n\n"
            f"If you believe this is a mistake, please contact platform support."
        )

    # ─────────────────────────────────────────────────────────
    # RESPONSE BUILDER
    # ─────────────────────────────────────────────────────────
    def _response(
        self,
        action: str,
        message: str,
        result: Optional[ModerationResult],
        profile: Dict[str, Any],
        sanitized_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "action":           action,           # allow | warn | block
            "message":         message,            # system message or original
            "sanitizedMessage": sanitized_message, # cleaned version if warn
            "violationCount":  profile.get("violationCount", 0),
            "isBlocked":       profile.get("isBlocked", False),
            "severity":        result.severity if result else None,
            "confidence":      result.confidence if result else None,
            "reason":          result.reason if result else None,
        }
