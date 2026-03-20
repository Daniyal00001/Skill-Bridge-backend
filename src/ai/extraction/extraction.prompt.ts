import { AgentSession } from '../shared/agent.types'

export function buildExtractionPrompt(session: AgentSession, availableSkills: string[]): string {
  return `
You are a senior software architect and project analyst for SkillBridge freelance platform.

Analyze the conversation below and extract structured project information.

CONVERSATION HISTORY:
${session.history.map(m => `${m.role.toUpperCase()}: ${m.content}`).join('\n\n')}

AVAILABLE SKILLS IN DATABASE:
${availableSkills.join(', ')}

INSTRUCTIONS:
1. Extract ALL project information mentioned anywhere in the conversation.
2. If a field is not mentioned, set it to null.
3. For features, extract every feature mentioned as an array of strings.
4. For budget, extract min and max as numbers in USD. If only one number mentioned, use it for both.
5. For timeline, extract as a human readable string e.g. "2 months", "8 weeks".
6. For techPreferences - ANALYZE the project deeply as a senior architect:
   - Look at projectType, platform, features, and complexity.
   - Pick the BEST matching technologies from the "AVAILABLE SKILLS IN DATABASE" list above.
   - If a core technology is not in the list but absolutely required, you may still include it.
   - NEVER leave techPreferences empty — always infer from project context.
7. For expertiseNeeded, infer from project complexity: "entry", "intermediate", or "senior".
8. For platform, extract e.g. "iOS", "Android", "iOS + Android", "Web", "Cross-platform".
9. For projectType, extract e.g. "Mobile App", "Web App", "REST API", "E-commerce", etc.

RETURN STRICT JSON ONLY. NO markdown. NO explanation. NO extra text.

{
  "projectType": string | null,
  "platform": string | null,
  "features": string[],
  "budgetMin": number | null,
  "budgetMax": number | null,
  "timeline": string | null,
  "techPreferences": string[],
  "expertiseNeeded": "entry" | "intermediate" | "senior" | null,
  "additionalNotes": string | null
}
`.trim()
}

export function buildExtractionCheckPrompt(session: AgentSession): string {
  return `
You are checking if enough project information has been collected to proceed to freelancer matching.

CURRENT EXTRACTED PROJECT DATA:
${JSON.stringify(session.project, null, 2)}

CONVERSATION HISTORY:
${session.history.map(m => `${m.role.toUpperCase()}: ${m.content}`).join('\n\n')}

REQUIRED FIELDS TO PROCEED:
- projectType (what kind of project)
- features (at least 1 feature)
- budgetMin and budgetMax (budget range)
- timeline (deadline or duration)

RETURN STRICT JSON ONLY:
{
  "isComplete": true | false,
  "missingFields": string[],
  "confidence": number
}
`.trim()
}