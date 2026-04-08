import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

from shared.constants import AgentStage
from shared.db import Database
from shared.redis_client import RedisClient # New import

class SessionService:
    def __init__(self, db=None):
        self._db = db
        self.REDIS_TTL = 3600 # 1 hour for active sessions

    async def get_db(self):
        if self._db is None:
            self._db = await Database.get_db()
        return self._db

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
        # 1. Try REDIS (Short-term)
        try:
            redis = await RedisClient.get_client()
            cached = await redis.get(f"ai_session:{session_id}")
            if cached:
                print(f"⚡ Session from Redis: {session_id}")
                return json.loads(cached)
        except Exception as e:
            print(f"⚠️ Redis get failed: {e}")

        # 2. Try MONGODB (Long-term)
        db = await self.get_db()
        session = await db.ai_sessions.find_one({
            "$or": [
                {"sessionId": session_id},
                {"_id": session_id}
            ]
        })
        
        if session and "_id" in session:
            session["_id"] = str(session["_id"])
            # Cache back to Redis
            try:
                redis = await RedisClient.get_client()
                await redis.setex(f"ai_session:{session_id}", self.REDIS_TTL, json.dumps(session, default=str))
            except: pass

        return session

    async def save(self, session: Dict[str, Any]):
        db = await self.get_db()
        session_id = session.get("sessionId")
        session["updatedAt"] = datetime.now().isoformat()
        
        # 1. Save to MONGODB
        to_mongo = {**session}
        if "_id" in to_mongo: del to_mongo["_id"]
        await db.ai_sessions.update_one(
            {"sessionId": session_id},
            {"$set": to_mongo},
            upsert=True
        )

        # 2. Save to REDIS
        try:
            redis = await RedisClient.get_client()
            await redis.setex(f"ai_session:{session_id}", self.REDIS_TTL, json.dumps(session, default=str))
        except Exception as e:
            print(f"⚠️ Redis save failed: {e}")

    async def get_or_create(self, session_id: str = None, client_name: str = "Client", client_id: str = None) -> Dict[str, Any]:
        if session_id:
            existing = await self.get(session_id)
            if existing:
                return existing
        return await self.create(client_name, client_id)

    async def update_stage(self, session_id: str, stage: AgentStage):
        db = await self.get_db()
        await db.ai_sessions.update_one(
            {"sessionId": session_id},
            {"$set": {"stage": stage, "updatedAt": datetime.now()}}
        )

    # 🧠 THE 30-DAY FETCH LOGIC (Memory)
    async def get_recent_history(self, client_id: str, days: int = 30) -> List[Dict[str, Any]]:
        db = await self.get_db()
        cutoff = datetime.now() - timedelta(days=days)
        
        # Fetch past sessions and insights for this client
        cursor = db.ai_sessions.find({
            "clientId": client_id,
            "createdAt": {"$gte": cutoff}
        }).sort("createdAt", -1).limit(10)
        
        history = await cursor.to_list(length=10)
        return history

