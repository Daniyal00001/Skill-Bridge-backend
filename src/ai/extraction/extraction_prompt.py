from typing import Dict, Any, List


def build_extraction_prompt(session: Dict[str, Any], available_skills: List[str]) -> str:
    history_text = "\n\n".join(
        f"{m['role'].upper()}: {m['content']}"
        for m in session.get("history", [])
    )
    skills_text = ", ".join(available_skills)

    return f"""
ROLE: Senior Software Architect & Project Analyst.
MISSION: Extract the 5 REQUIRED PROJECT FIELDS from the conversation history.

CONVERSATION HISTORY:
{history_text}

REFERENCE SKILLS (Use these for 'techPreferences' if they match):
{skills_text}

EXTRACTION RULES:
1. PROJECT GOAL: What is the core idea? (Extract into 'projectType')
2. FEATURES: List of specific functionalities mentioned.
3. BUDGET: Extract number or range. If a single number, set budgetMin and budgetMax to that value.
4. TIMELINE: Extract duration or deadline.
5. PLATFORM: Web, iOS, Android, Desktop, AI System, etc.

ADDITIONAL INFERENCE:
- techPreferences: Based on the Platform and Features, pick the BEST stack. prioritize the REFERENCE SKILLS list.
- expertiseNeeded: "entry", "intermediate", or "senior" based on technical complexity.

RETURN STRICT JSON ONLY:
{{
  "projectType": string | null,
  "platform": string | null,
  "features": string[],
  "budgetMin": number | null,
  "budgetMax": number | null,
  "timeline": string | null,
  "techPreferences": string[],
  "expertiseNeeded": "entry" | "intermediate" | "senior" | null,
  "additionalNotes": string | null
}}
""".strip()


def build_extraction_check_prompt(session: Dict[str, Any]) -> str:
    import json
    project_json = json.dumps(session.get("project", {}), indent=2)

    return f"""
DECISION ENGINE: Is this project ready for matching?

CURRENT PROJECT DATA:
{project_json}

HARD REQUIRMENTS (ALL MUST BE PRESENT):
1. Project Idea/Goal (projectType)
2. Features (features list cannot be empty)
3. Budget (budgetMin or budgetMax)
4. Timeline (timeline)
5. Platform (platform)
6. Tech Stack (techPreferences list cannot be empty)

PROTOCOL: If ANY field is missing, 'isComplete' MUST be FALSE.

RETURN STRICT JSON ONLY:
{{
  "isComplete": boolean,
  "missingFields": string[],
  "confidence": number (0-100)
}}
""".strip()