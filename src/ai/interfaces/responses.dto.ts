export interface AnalysisResponseDto {
    extractedSkills: string[];
    complexity: 'Low' | 'Medium' | 'High';
    estimatedRealisticTimeline: string;
    riskFactors?: string[];
}

export interface MatchResponseDto {
    matches: Array<{
        freelancerId: string;
        name: string;
        similarityScore: number;
        matchingSkills: string[];
        reasoning: string;
    }>;
}

export interface NegotiationResponseDto {
    draft: string;
}

export interface ContractResponseDto {
    contractDraft: string | object;
}
