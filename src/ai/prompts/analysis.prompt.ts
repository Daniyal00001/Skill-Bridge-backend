export const buildAnalysisPrompt = (params: {
    description: string;
    budget: number;
    clientProposedTimeline: string;
}) => {
    return `
You are an AI project evaluation engine inside a freelance marketplace.

Analyze the following project:

Description:
${params.description}

Budget:
${params.budget}

Client Proposed Timeline:
${params.clientProposedTimeline}

Your task:
1. Extract required technical skills
2. Determine project complexity (Low, Medium, High)
3. Estimate realistic timeline
4. Identify potential risk factors

Respond ONLY in valid JSON format:

{
  "extractedSkills": ["skill1", "skill2"],
  "complexity": "Low | Medium | High",
  "estimatedRealisticTimeline": "string",
  "riskFactors": ["risk1", "risk2"]
}
`;
};