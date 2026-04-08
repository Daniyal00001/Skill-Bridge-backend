from typing import Dict, List, Any

class ExpertiseLevel:
    BEGINNER = "BEGINNER"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"

def get_missing_fields(project: Dict[str, Any]) -> List[str]:
    """Identifies missing core project requirements."""
    missing = []
    
    # 1. Project Goal/Idea
    if not project.get("projectType") or len(str(project.get("projectType"))) < 3:
        missing.append("Specific project goal or idea")

    # 2. Key Features
    if not project.get("features") or len(project.get("features", [])) == 0:
        missing.append("Key features list")

    # 3. Budget
    if not project.get("budgetMin") and not project.get("budget"):
        missing.append("Budget (number or range in USD)")

    # 4. Timeline
    if not project.get("timeline"):
        missing.append("Project timeline (deadline or duration)")

    # 5. Platform
    if not project.get("platform"):
        missing.append("Target platform (Web, Mobile, AI system, etc.)")

    return missing

def build_conversation_system_prompt(
    persona: Dict[str, Any],
    project: Dict[str, Any],
    client_name: str,
    session: Dict[str, Any],
    conversation_round: int = 0
) -> str:
    """Generates a high-precision, persona-adaptive system prompt for FreelanceAI."""
    
    missing_fields = get_missing_fields(project)
    is_complete = len(missing_fields) == 0

    expertise = persona.get("expertiseLevel", "BEGINNER")
    user_type = persona.get("userType", "confused")
    urgency = persona.get("urgency", "low")
    budget_sens = persona.get("budgetSensitivity", "medium")
    comm_style = persona.get("communicationStyle", "formal")
    goal = persona.get("primaryGoal", "Build a project")

    # 1. Base expertise behavior
    expertise_logic = {
        "BEGINNER": "- Client is a BEGINNER. Be warm and patient. Suggest options. Use NO jargon.",
        "INTERMEDIATE": "- Client is INTERMEDIATE. Be professional and concise. Ask targeted technical questions.",
        "ADVANCED": "- Client is ADVANCED. Be direct, technical, and skip all basics."
    }.get(expertise, "- Provide helpful guidance.")

    # 2. User Type Adaptation
    type_logic = {
        "business_owner": "- FOCUS: ROI, timeline, and business value. Use business-oriented language.",
        "student": "- FOCUS: Suggest MVP, learning, and affordable/low-cost options.",
        "startup": "- FOCUS: Speed to market, MVP features, and scalability.",
        "technical": "- FOCUS: Skip explanations of 'how things work'. Use technical terms (API, DB, Frameworks).",
        "experienced_client": "- FOCUS: Efficiency. Move fast. Skip long explanations. Be high-level.",
        "confused": "- FOCUS: Discovery. Ask deep questions to uncover their true project goal."
    }.get(user_type, "- Be a helpful consultant.")

    # 3. Urgency & Budget Logic
    urgency_msg = "🚨 URGENT: Fast-track the conversation. Get essentials quickly." if urgency == "high" else ""
    budget_msg = "💰 BUDGET SENSITIVE: Prioritize affordable and cost-effective solutions." if budget_sens == "high" else ""

    # 4. Long-term memory context
    memory = session.get("persistentMemory")
    memory_context = ""
    if memory:
        past_projects = memory.get('pastProjects', [])
        projects_summary = ""
        if past_projects:
            projects_summary = "- Recent past discussions: " + "; ".join([p.get('summary') for p in past_projects[:3]])

        memory_context = f"""
RETURNING CLIENT CONTEXT:
- Previous Expertise: {memory.get('expertiseLevel', 'beginner')}
- Communication Style: {memory.get('communicationStyle', 'formal')}
{projects_summary}
- Hired Previously: {", ".join(memory.get('hiredFreelancers', []))}
- Don't Recommend: {", ".join(memory.get('rejectedFreelancers', []))}
(Do not re-ask questions already answered in past sessions. Reference their previous project if relevant to build trust.)
"""

    return f"""
ROLE: You are the FreelanceAI Agent — an elite Project Architect.
CLIENT: {client_name}
PERSONA: {user_type.upper()} ({expertise}) | Goal: {goal}
STYLE: {comm_style.upper()}

{memory_context}

CORE PROTOCOL:
1. DOMAIN ENFORCEMENT: Handle only freelancing/project queries.
2. ADAPTIVE STRATEGY:
   {expertise_logic}
   {type_logic}
   {urgency_msg}
   {budget_msg}

3. DECISION ENGINE (HARD GATE):
   - Internal Check: Goal, Features, Budget, Timeline, Platform?
   - If ANY = No: Stay in 'UNDERSTAND' mode. Ask ONLY for missing fields.
   - If ALL = Yes: Provide Project Summary + Feasibility Analysis.

REQUIRED DATA STATUS:
{chr(10).join([f"❌ MISSING: {f}" for f in missing_fields]) if missing_fields else "✅ COMPLETE: All info collected."}

TONE: {"Formal and professional" if comm_style == "formal" else "Casual and friendly"}

FINAL INSTRUCTION: 
{"Great! We have the data. Move to matching now." if is_complete else "Focus on the missing fields based on the persona rules above."}
""".strip()