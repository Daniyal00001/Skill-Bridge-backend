# ============================================================
# PATH: backend/ai/memory/session_service.py
# PURPOSE: Stores and retrieves agent session from Redis/Memory
# ============================================================

import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from shared.constants import AgentStage, SESSION_TTL_SECONDS

class SessionService:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.in_memory_db = {}  # Fallback if Redis is not available

    def _key(self, session_id: str) -> str:
        return f"agent_session:{session_id}"

    async def create(self, client_name: str = "Client", client_id: str = None) -> Dict[str, Any]:
        session_id = str(uuid.uuid4())
        session = {
            "sessionId": session_id,
            "clientId": client_id,
            "clientName": client_name,
            "stage": AgentStage.UNDERSTAND,
            "history": [],
            "project": {},
            "createdAt": datetime.now().isoformat(),
            "updatedAt": datetime.now().isoformat(),
        }
        await self.save(session)
        return session

    async def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        if self.redis:
            raw = await self.redis.get(self._key(session_id))
            if raw:
                return json.loads(raw)
        return self.in_memory_db.get(session_id)

    async def save(self, session: Dict[str, Any]):
        session_id = session["sessionId"]
        session["updatedAt"] = datetime.now().isoformat()
        
        if self.redis:
            await self.redis.set(
                self._key(session_id),
                json.dumps(session),
                ex=SESSION_TTL_SECONDS
            )
        else:
            self.in_memory_db[session_id] = session

    async def get_or_create(self, session_id: str = None, client_name: str = "Client") -> Dict[str, Any]:
        if session_id:
            existing = await self.get(session_id)
            if existing:
                return existing
        return await self.create(client_name)

    async def update_stage(self, session_id: str, stage: AgentStage):
        session = await self.get(session_id)
        if session:
            session["stage"] = stage
            await self.save(session)
