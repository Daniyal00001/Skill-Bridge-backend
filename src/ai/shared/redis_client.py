import redis.asyncio as redis
import os
from dotenv import load_dotenv

load_dotenv()

class RedisClient:
    _instance = None
    _client = None

    @classmethod
    async def get_client(cls):
        if cls._client is None:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
            cls._client = redis.from_url(redis_url, decode_responses=True)
            print(f"🔌 Connected to Redis at {redis_url}")
        return cls._client

    @classmethod
    async def close(cls):
        if cls._client:
            await cls._client.close()
            cls._client = None
