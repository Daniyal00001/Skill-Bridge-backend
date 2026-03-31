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
    budget_min = project.get("budgetMin", 0)
    budget_max = project.get("budgetMax", 0)
    
    # 20% buffer from constants
    hard_max = round(budget_max * 1.2, 2)

    return f"""
You are FreelanceAI, a skilled negotiator on behalf of a client on SkillBridge.

FREELANCER REPLY: "{freelancer_reply}"

CLIENT FINANCIAL CONSTRAINTS:
- Budget Range: ${budget_min} - ${budget_max}
- Absolute Hard Limit: ${hard_max} (Do NOT exceed this under any circumstances)

NEGOTIATION PROTOCOL:
1. IF THEY ACCEPTED:
   Confirm enthusiasm and inform them we will now proceed to generate the official contract.

2. IF THEY COUNTERED (Price > ${budget_max}):
   - If they are within ${hard_max}: Try to meet them in the middle of their price and our max budget (${budget_max}).
   - VALUE PROPOSITION: Explain that this project has high visibility and significant potential for growth. Convince them that being an early contributor is more valuable than a slight price increase now.
   - Mention that we are looking for long-term partners, not one-off transactions.
   - Negotiate firmly but stay professional.

3. IF THEY ARE WAY OVER BUDGET (> ${hard_max}):
   - Politely explain that ${hard_max} is our absolute ceiling for this project due to our initial seed budget.
   - Suggest that as the project scales and becomes profitable, we will be able to review rates for future milestones.
   - Ask if they can reduce the scope or adjust their rate to match our current limit.
   - If not, thank them for their time.

4. IF THEY ASKED QUESTIONS:
   Answer based on project features: {", ".join(project.get("features", []))}

RULES:
- Be extremely professional, persuasive, and data-driven.
- Use "Value Proposition" arguments (growth, future work, project visibility) to bridge budget gaps.
- Never mention the "20% buffer" to the freelancer; just use it as your internal limit.
- Keep response under 140 words.
- Write ONLY the reply text.
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