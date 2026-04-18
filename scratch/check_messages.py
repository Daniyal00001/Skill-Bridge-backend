
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

async def check_db():
    client = AsyncIOMotorClient(os.getenv("DATABASE_URL"))
    db = client.get_database()
    
    print("\n--- Latest Chat Rooms ---")
    rooms = await db.chat_rooms.find().sort("createdAt", -1).limit(5).to_list(5)
    for r in rooms:
        print(f"ID: {r['_id']}, Client: {r['clientProfileId']}, Freelancer: {r['freelancerProfileId']}, Project: {r.get('projectId')}")
        
    print("\n--- Latest Messages ---")
    messages = await db.messages.find().sort("sentAt", -1).limit(5).to_list(5)
    for m in messages:
        print(f"ID: {m['_id']}, Room: {m['chatRoomId']}, Sender: {m['senderId']}, Content: {m['content'][:50]}...")

if __name__ == "__main__":
    asyncio.run(check_db())
