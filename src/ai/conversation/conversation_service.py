from typing import Dict, Any, List
from conversation.conversation_prompt import build_conversation_system_prompt
from shared.constants import (
    ExpertiseLevel,
    UserType,
    UrgencyLevel,
    BudgetSensitivity,
    CommunicationStyle
)
import json
import re


class ConversationService:
    def __init__(self, llm_service, session_service):
        self.llm = llm_service
        self.session_service = session_service

    async def handle(self, session: Dict[str, Any], user_message: str) -> str:

        # 1. Detect user persona
        if not session.get("persona"):
            session["persona"] = await self.detect_user_persona_llm(user_message)
            print(f"👤 Persona detected: {session['persona'].get('userType', 'unknown')}")

        # 2. Conversation round
        history = session.get("history", [])
        conversation_round = len(history) // 2

        # 3. Build prompt
        system_prompt = build_conversation_system_prompt(
            session["persona"],
            session.get("project", {}),
            session.get("clientName", "Client"),
            conversation_round
        )

        # 4. Messages
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": user_message})

        # 5. LLM call
        reply = await self.llm.call(messages)

        # 6. Save history
        history.append({"role": "user", "content": user_message})
        history.append({"role": "assistant", "content": reply})
        session["history"] = history

        await self.session_service.save(session)

        return reply

    async def detect_user_persona_llm(self, message: str) -> Dict[str, Any]:
        try:
            prompt = f"""
Analyze this user message and determine their persona for a freelance platform.
MESSAGE: "{message}"

PERSONA CATEGORIES:
- expertiseLevel: BEGINNER, INTERMEDIATE, ADVANCED
- userType: business_owner, student, startup, technical, experienced_client, confused
- urgency: low, medium, high
- budgetSensitivity: low, medium, high
- communicationStyle: formal, casual
- primaryGoal: A short string (3-5 words)

RETURN STRICT JSON ONLY:
{{
  "expertiseLevel": "...",
  "userType": "...",
  "urgency": "...",
  "budgetSensitivity": "...",
  "communicationStyle": "...",
  "primaryGoal": "..."
}}
"""
            result = await self.llm.call([{"role": "user", "content": prompt}])
            cleaned = re.sub(r"```json|```", "", result, flags=re.IGNORECASE).strip()
            persona = json.loads(cleaned)
            return persona

        except Exception as e:
            print(f"❌ Persona detection failed: {e}")
            return {
                "expertiseLevel": ExpertiseLevel.INTERMEDIATE,
                "userType": UserType.CONFUSED,
                "urgency": UrgencyLevel.LOW,
                "budgetSensitivity": BudgetSensitivity.MEDIUM,
                "communicationStyle": CommunicationStyle.FORMAL,
                "primaryGoal": "Establish project requirements"
            }

    def is_project_complete(self, project: Dict[str, Any]) -> bool:
        return all([
            project.get("projectType"),
            project.get("features"),
            project.get("budgetMin"),
            project.get("budgetMax"),
            project.get("timeline")
        ])