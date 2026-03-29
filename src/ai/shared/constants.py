# ============================================================
# PATH: backend / ai / shared / constants.py
# PURPOSE: All constants used across the AI agent modules
# ============================================================

from enum import Enum

# ── LLM Config ───────────────────────────────────────────────
LLM_MODEL = "llama-3.3-70b-versatile"
LLM_MAX_TOKENS = 500
LLM_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"

# ── Agent Stages ─────────────────────────────────────────────
class AgentStage(str, Enum):
    UNDERSTAND = "UNDERSTAND"   # Gathering project info from client
    ANALYZE = "ANALYZE"      # Feasibility + project summary
    MATCH = "MATCH"        # Finding best freelancers from DB
    OUTREACH = "OUTREACH"     # Sending messages to freelancers
    NEGOTIATE = "NEGOTIATE"    # Handling freelancer replies
    CONTRACT = "CONTRACT"     # Generating final contract
    DONE = "DONE"         # Everything complete

# ── User Expertise Levels ─────────────────────────────────────
class ExpertiseLevel(str, Enum):
    BEGINNER = "BEGINNER"      # Vague idea, needs full guidance
    INTERMEDIATE = "INTERMEDIATE"  # Has some clarity, needs refinement
    ADVANCED = "ADVANCED"      # Knows exactly what they want

class UserType(str, Enum):
    BUSINESS_OWNER = "business_owner"
    STUDENT = "student"
    STARTUP = "startup"
    TECHNICAL = "technical"
    EXPERIENCED_CLIENT = "experienced_client"
    CONFUSED = "confused"

class UrgencyLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class BudgetSensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class CommunicationStyle(str, Enum):
    FORMAL = "formal"
    CASUAL = "casual"

# ── Session Config ────────────────────────────────────────────
SESSION_TTL_SECONDS = 60 * 60 * 2   # 2 hours
SESSION_PREFIX = "ai:session:"

# ── Matching Config ───────────────────────────────────────────
MIN_FREELANCER_RATING = 4.5
MAX_BUDGET_OVERAGE_PERCENT = 20     # Allow 20 % over client budget
TOP_MATCHES_LIMIT = 10

# ── Negotiation Config ────────────────────────────────────────
MAX_NEGOTIATION_ROUNDS = 3

# ── Extraction: Required fields to consider project "complete" ─
REQUIRED_PROJECT_FIELDS = [
  "projectType",
  "features",
  "budgetMin",
  "budgetMax",
  "timeline",
]