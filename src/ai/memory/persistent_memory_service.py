# ============================================================
# PATH: backend/ai/memory/persistent_memory_service.py
# PURPOSE: Handles 30-day long-term memory in MongoDB
# ============================================================

from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from shared.db import Database
from shared.agent_types import PersistentMemory

class PersistentMemoryService:
    def __init__(self, db=None):
        self._db = db

    async def get_db(self):
        if self._db is None:
            self._db = await Database.get_db()
        return self._db

    async def get(self, user_id: str) -> Optional[PersistentMemory]:
        db = await self.get_db()
        # MongoDB collection name is "ai_memories" as per schema.prisma @map
        data = await db.ai_memories.find_one({"userId": user_id})
        
        if not data:
            return None
            
        # Check if expired
        if data.get("expiresAt") and data["expiresAt"] < datetime.now():
            await self.delete(user_id)
            return None
            
        memories = data.get("memories", {})
        return PersistentMemory(userId=user_id, **memories)

    async def save(self, user_id: str, memory: PersistentMemory):
        db = await self.get_db()
        
        # Calculate expiry (30 days from now)
        expires_at = datetime.now() + timedelta(days=30)
        
        # Prepare document for MongoDB
        # Prisma Json corresponds to 'memories' field
        memory_data = memory.dict()
        if "userId" in memory_data:
            del memory_data["userId"] # We store it at root level

        await db.ai_memories.update_one(
            {"userId": user_id},
            {
                "$set": {
                    "memories": memory_data,
                    "updatedAt": datetime.now(),
                    "expiresAt": expires_at
                }
            },
            upsert=True
        )

    async def delete(self, user_id: str):
        db = await self.get_db()
        await db.ai_memories.delete_one({"userId": user_id})

    async def update_preferences(self, user_id: str, new_data: Dict[str, Any]):
        """
        Incrementally update memory during/after a session
        """
        current = await self.get(user_id) or PersistentMemory(userId=user_id)
        
        # Merge logic
        if "expertiseLevel" in new_data:
            current.expertiseLevel = new_data["expertiseLevel"]
        if "communicationStyle" in new_data:
            current.communicationStyle = new_data["communicationStyle"]
        if "budgetRange" in new_data:
            current.budgetRange = new_data["budgetRange"]
        if "hiredFreelancer" in new_data:
            if new_data["hiredFreelancer"] not in current.hiredFreelancers:
                current.hiredFreelancers.append(new_data["hiredFreelancer"])
        if "rejectedFreelancer" in new_data:
            if new_data["rejectedFreelancer"] not in current.rejectedFreelancers:
                current.rejectedFreelancers.append(new_data["rejectedFreelancer"])
        if "pastProject" in new_data:
            # Prepend the newest project to memory for reference
            current.pastProjects.insert(0, new_data["pastProject"])
            # Keep only the last 5 projects for memory context
            current.pastProjects = current.pastProjects[:5]
        
        current.totalSessions += 1
        current.lastActiveAt = datetime.now()
        
        await self.save(user_id, current)
        return current
