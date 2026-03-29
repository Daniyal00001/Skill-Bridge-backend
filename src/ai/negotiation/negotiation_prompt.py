# ============================================================
# PATH: backend/ai/negotiation/negotiation_prompt.py
# PURPOSE: Prompt builders for negotiation module
# ============================================================

from typing import Any, Dict


def build_negotiation_outreach_prompt(session: Dict[str, Any], freelancer: Dict[str, Any]) -> str:
    project = session.get("project") or {}
    features = project.get("features") or []
    skills = freelancer.get("skills") or []

    return f"""
You are FreelanceAI, representing a client on SkillBridge freelance platform.

Write a professional outreach message to a freelancer on behalf of the client.

PROJECT DETAILS:
- Type: {project.get("projectType") or "Software Project"}
- Platform: {project.get("platform") or "Not specified"}
- Features: {", ".join(features) or "Not specified"}
- Budget: ${project.get("budgetMin")} - ${project.get("budgetMax")}
- Timeline: {project.get("timeline")}

FREELANCER:
- Name: {freelancer.get("name")}
- Skills: {", ".join(skills)}
- Rate: ${freelancer.get("hourlyRate")}/hr
- Location: {freelancer.get("location")}

RULES:
1. Be professional and friendly
2. Mention specific skills that match the project
3. State the budget and timeline clearly
4. Ask if they are available and interested
5. Keep it under 150 words
6. Do NOT make up information

Write the outreach message only. No subject line needed.
""".strip()


def build_negotiation_reply_prompt(
    session: Dict[str, Any],
    freelancer: Dict[str, Any],
    freelancer_reply: str,
) -> str:
    project = session.get("project") or {}

    return f"""
You are FreelanceAI, negotiating on behalf of a client on SkillBridge.

The freelancer has replied to our outreach. Analyze their reply and respond appropriately.

PROJECT:
- Budget: ${project.get("budgetMin")} - ${project.get("budgetMax")}
- Timeline: {project.get("timeline")}
- Type: {project.get("projectType")}

FREELANCER: {freelancer.get("name")}
THEIR REPLY: "{freelancer_reply}"

YOUR TASK:
1. If they ACCEPTED → Confirm and say we will proceed to contract
2. If they COUNTERED with higher price → Try to negotiate within 20% of max budget
3. If they are UNAVAILABLE → Thank them and say we will contact another freelancer
4. If they asked QUESTIONS → Answer based on project details

RULES:
- Be professional and concise
- Never exceed the budget by more than 20%
- Keep response under 100 words

Write the reply message only.
""".strip()


def build_negotiation_analysis_prompt(freelancer_reply: str, budget_max: float) -> str:
    return f"""
Analyze this freelancer reply and extract structured data.

FREELANCER REPLY: "{freelancer_reply}"
CLIENT MAX BUDGET: ${budget_max}

Determine:
1. Status: ACCEPTED, COUNTERED, DECLINED, or QUESTIONS
2. If they mentioned a price, extract it
3. If they are available or not

RETURN STRICT JSON ONLY:
{{
  "status": "ACCEPTED" | "COUNTERED" | "DECLINED" | "QUESTIONS",
  "proposedPrice": number | null,
  "isAvailable": true | false,
  "summary": string
}}
""".strip()