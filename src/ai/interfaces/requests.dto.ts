export interface AnalyzeProjectRequestDto {
    projectId: string;
    description: string;
    budget: number;
    clientProposedTimeline: string;
}

export interface MatchFreelancerRequestDto {
    projectDescription: string;
    extractedSkills?: string[];
}

export interface GenerateNegotiationRequestDto {
    projectId: string;
    clientId: string;
    freelancerId: string;
    recentMessagesContext?: Array<{ senderId: string; message: string; timestamp: Date }>;
}

export interface GenerateContractRequestDto {
    projectDetails: any;
    agreedTerms: any;
    milestones: Array<{ title: string; amount: number; dueDate: Date }>;
    paymentTerms: any;
}
