# ============================================================
# PATH: backend/src/ai/shared/db.py
# PURPOSE: Async MongoDB connection for AI services (using Motor)
# ============================================================

import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load .env relative to this file's root (src/ai)
load_dotenv(os.path.join(os.path.dirname(__file__), "../../../.env"))

DATABASE_URL = os.getenv("DATABASE_URL")

class Database:
    _client: AsyncIOMotorClient = None
    _db = None

    @classmethod
    async def connect(cls):
        if cls._client is None:
            if not DATABASE_URL:
                raise ValueError("DATABASE_URL not found in environment!")
            
            # Note: MongoDB connection string might need +srv if it's atlas, 
            # but user has mongodb://127.0.0.1:27017/skillbridge
            cls._client = AsyncIOMotorClient(DATABASE_URL)
            
            # Resolve DB name from URI or use default
            db_name = DATABASE_URL.split("/")[-1].split("?")[0] or "skillbridge"
            cls._db = cls._client[db_name]
            print(f"[DB] Connected to MongoDB: {db_name}")

    @classmethod
    async def get_db(cls):
        if cls._client is None:
            await cls.connect()
        return cls._db

    @classmethod
    async def close(cls):
        if cls._client:
            cls._client.close()
            cls._client = None
