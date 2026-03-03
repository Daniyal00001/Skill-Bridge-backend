import { LlmService } from './llm.service';
import { buildAnalysisPrompt } from '../prompts/analysis.prompt';

interface AnalysisResult {
    extractedSkills: string[];
    complexity: 'Low' | 'Medium' | 'High';
    estimatedRealisticTimeline: string;
    riskFactors?: string[];
}

export class AnalysisService {
    private llmService: LlmService;

    constructor() {
        this.llmService = new LlmService();
    }

    async analyzeProject(params: {
        projectId: string;
        description: string;
        budget: number;
        clientProposedTimeline: string;
    }): Promise<AnalysisResult> {

        const prompt = buildAnalysisPrompt({
            description: params.description,
            budget: params.budget,
            clientProposedTimeline: params.clientProposedTimeline
        });

        const response = await this.llmService.chat([
            { role: "system", content: "You are a structured JSON API generator." },
            { role: "user", content: prompt }
        ]);

        try {
            const parsed = JSON.parse(response);
            return parsed;
        } catch (error) {
            throw new Error("Invalid JSON response from LLM");
        }
    }
}