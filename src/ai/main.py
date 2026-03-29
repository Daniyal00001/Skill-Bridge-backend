# ============================================================
# PATH: backend/ai/main.py
# PURPOSE: Main entry point for Python AI backend (FastAPI)
# ============================================================

import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Import routers
from assistant_controller import router as assistant_router
from coverLetter_controller import router as cover_letter_router

# Load .env from backend root
load_dotenv(os.path.join(os.path.dirname(__file__), "../../.env"))

app = FastAPI(title="SkillBridge AI Agent", version="1.0.0")

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In prod, specify the Node backend or frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────
app.include_router(assistant_router)
app.include_router(cover_letter_router)

@app.get("/")
def read_root():
    return {"status": "AI Backend Online"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
