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
    budget_max = project.get("budgetMax", 0)
    project_name = project.get("projectType") or "this project"
    project_scope = project.get("additionalNotes") or "well-defined project features"
    timeline = project.get("timeline") or "flexible"
    
    negotiation_state = session.get("negotiationState", {})
    current_round = negotiation_state.get("round", 1)
    
    return f"""
ROLE: You are an AI Negotiation Agent representing a client on the SkillBridge platform.
MISSION: Negotiate professionally on behalf of the client to reach an agreement within the budget ceiling of ${budget_max}.

FREELANCER REPLY: "{freelancer_reply}"
PROJECT: {project_name}
SCOPE: {project_scope}
TIMELINE: {timeline}

NEGOTIATION RULES:

1. BUDGET AWARENESS & CEILING:
   - The absolute maximum budget is ${budget_max}. Never suggest or accept a higher amount.
   - If the freelancer quotes above this, you must politely counteroffer or explain the constraint.

2. LOGICAL BREAKDOWN (FINANCIAL TRANSPARENCY):
   - Break down the numbers for the freelancer to show the budget is reasonable.
   - Estimate approximate project costs: API subscriptions (~$50), Hosting (~$30), and Testing/Tools (~$20).
   - Calculate and mention the potential 'Freelancer Profit' after these costs are covered.
   - Example reasoning: "Your quote is $400, but with your budget, after accounting for $100 in tool costs, you still retain a good clear profit for your labor."

3. JUSTIFYING THE BUDGET:
   - Explain why the client’s budget is fair based on:
     a) Clear Project Scope: Minimal risk of scope creep.
     b) Timeline: {timeline}.
     c) Clarity: Requirements are well-defined.

4. VALUE PROPOSITION (FUTURE BENEFITS):
   - Highlight the long-term value:
     - Potential for repeat projects and long-term partnership.
     - Guaranteed 5-star review upon successful delivery.
     - Significant reputation growth on the SkillBridge platform.

5. COMMUNICATION STYLE:
   - Tone: Friendly, professional, persuasive, and respectful. Always make them feel valued.

6. NEGOTIATION ROUND: {current_round}/3
   - If this is round 3 and no agreement is reached, politely state that you'll have to check with the client for final approval.

OUTPUT INSTRUCTION:
Draft the direct message to the freelancer as if you are the client. Do not include any meta-talk or subject lines.
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