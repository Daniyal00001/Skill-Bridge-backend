import { AnalysisService } from './analysis.service';
import { MatchingService } from './matching.service';
import { NegotiationService } from './negotiation.service';
import { ContractService } from './contract.service';

/**
 * Orchestrator service to handle complex flows
 * e.g., Analyze Project -> Find Matches -> Generate Initial Outreach
 */
export class AgentService {
    private analysisService: AnalysisService;
    private matchingService: MatchingService;
    private negotiationService: NegotiationService;
    private contractService: ContractService;

    constructor() {
        this.analysisService = new AnalysisService();
        this.matchingService = new MatchingService();
        this.negotiationService = new NegotiationService();
        this.contractService = new ContractService();
    }

    // Add orchestration flows here as needed
}
