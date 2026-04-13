# ============================================================
# PATH: backend/ai/coverLetter_controller.py
# PURPOSE: FastAPI endpoint for generating elite cover letters
# ============================================================

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from shared.llm_service import LLMService

from shared.db import Database
from bson import ObjectId

router = APIRouter(prefix="/api/ai", tags=["AI"])
llm = LLMService()

class CoverLetterRequest(BaseModel):
    projectId: str
    userName: Optional[str] = "The Freelancer"
    experience: Optional[str] = "Expert Developer"
    skills: Optional[str] = "Relevant stack"
    bio: Optional[str] = ""
    tone: Optional[str] = "Professional" # [Professional, Enthusiastic, Concise, Direct, Creative, Bold]
    portfolio: Optional[str] = "N/A"
    certificates: Optional[str] = "N/A"

class CoverLetterResponse(BaseModel):
    success: bool
    result: str

@router.post("/cover-letter", response_model=CoverLetterResponse)
async def handle_generate_cover_letter(body: CoverLetterRequest):
    try:
        # 1. Fetch real Project data from MongoDB
        db = await Database.get_db()
        project_data = {}
        if db is not None:
            try:
                project_data = await db.projects.find_one({"_id": ObjectId(body.projectId)})
            except Exception:
                pass
        
        project_title = project_data.get("title", "this project")
        project_desc = project_data.get("description", "detailed technical requirements")

        # 2. Build instructions based on Tone
        tone_map = {
            "Professional": "formal, polite, and detailed",
            "Enthusiastic": "friendly, energetic, and highly positive",
            "Concise": "short, precise, and high impact",
            "Direct": "to the point and assertive",
            "Creative": "imaginative, storytelling-focused, and engaging",
            "Bold": "confident, persuasive, and using proactive language"
        }
        tone_instruction = tone_map.get(body.tone, "professional and tailored")

        # 3. Create Upgraded Prompt
        prompt = f"""
ROLE: Senior AI writing assistant for elite freelancers.
MISSION: Create a world-class, tailored cover letter.

INPUT DATA:
- FREELANCER: {body.userName} (Bio: {body.bio})
- SKILLS: {body.skills}
- EXPERIENCE: {body.experience}
- PORTFOLIO: {body.portfolio}
- JOB TITLE: {project_title}
- JOB DESCRIPTION: {project_desc}
- SELECTED TONE: {body.tone} ({tone_instruction})

STRICT OUTPUT RULES:
1. Include a short, impactful **Subject Line** at the top.
2. Address the client professionally.
3. Highlight specific matches between skills and the job description.
4. No generic filler or templates.
5. Follow the {body.tone} style exactly in sentence structure and word choice.
6. FORMAT: Return only the letter in HTML with <p> tags. 

MISSION: Output ONLY the localized, persuasive letter.
"""

        result_raw = await llm.call([
            {"role": "system", "content": "You are a senior AI writing assistant specialized in generating high-quality cover letters."},
            {"role": "user", "content": prompt}
        ], task="cover_letter")

        # 4. Clean and format for frontend
        result = result_raw.strip()
        # Wrap in <p> if LLM forgot
        if not result.startswith("<"):
            lines = [line.strip() for line in result.split("\n") if line.strip()]
            result = "".join([f"<p>{line}</p>" for line in lines])

        return CoverLetterResponse(success=True, result=result)

    except Exception as e:
        print(f"❌ AI Cover Letter Generation Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate cover letter.")
