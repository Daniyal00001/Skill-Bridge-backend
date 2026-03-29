import asyncio
from shared.db import Database

async def check():
    await Database.connect()
    db = await Database.get_db()
    
    avail = await db.freelancer_profiles.distinct("availability")
    print(f"Availability Statuses: {avail}")
    
    # Check if SkillLinks actually point to valid IDs
    link = await db.freelancer_skills.find_one()
    print(f"Sample Link: {link}")
    
    p = await db.freelancer_profiles.find_one({"_id": link["freelancerProfileId"]})
    print(f"Found Profile from Link: {p is not None}")

if __name__ == "__main__":
    asyncio.run(check())
