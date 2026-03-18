import { AgentSession, MatchedFreelancer } from '../shared/agent.types'

export function buildNegotiationOutreachPrompt(
    session: AgentSession,
    freelancer: MatchedFreelancer
): string {
    const project = session.project
    return `
You are FreelanceAI, representing a client on SkillBridge freelance platform.

Write a professional outreach message to a freelancer on behalf of the client.

PROJECT DETAILS:
- Type: ${project?.projectType || 'Software Project'}
- Platform: ${project?.platform || 'Not specified'}
- Features: ${project?.features?.join(', ') || 'Not specified'}
- Budget: $${project?.budgetMin} - $${project?.budgetMax}
- Timeline: ${project?.timeline}

FREELANCER:
- Name: ${freelancer.name}
- Skills: ${freelancer.skills.join(', ')}
- Rate: $${freelancer.hourlyRate}/hr
- Location: ${freelancer.location}

RULES:
1. Be professional and friendly
2. Mention specific skills that match the project
3. State the budget and timeline clearly
4. Ask if they are available and interested
5. Keep it under 150 words
6. Do NOT make up information

Write the outreach message only. No subject line needed.
`.trim()
}

export function buildNegotiationReplyPrompt(
    session: AgentSession,
    freelancer: MatchedFreelancer,
    freelancerReply: string
): string {
    const project = session.project
    return `
You are FreelanceAI, negotiating on behalf of a client on SkillBridge.

The freelancer has replied to our outreach. Analyze their reply and respond appropriately.

PROJECT:
- Budget: $${project?.budgetMin} - $${project?.budgetMax}
- Timeline: ${project?.timeline}
- Type: ${project?.projectType}

FREELANCER: ${freelancer.name}
THEIR REPLY: "${freelancerReply}"

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
`.trim()
}

export function buildNegotiationAnalysisPrompt(
    freelancerReply: string,
    budgetMax: number
): string {
    return `
Analyze this freelancer reply and extract structured data.

FREELANCER REPLY: "${freelancerReply}"
CLIENT MAX BUDGET: $${budgetMax}

Determine:
1. Status: ACCEPTED, COUNTERED, DECLINED, or QUESTIONS
2. If they mentioned a price, extract it
3. If they are available or not

RETURN STRICT JSON ONLY:
{
  "status": "ACCEPTED" | "COUNTERED" | "DECLINED" | "QUESTIONS",
  "proposedPrice": number | null,
  "isAvailable": true | false,
  "summary": string
}
`.trim()
}