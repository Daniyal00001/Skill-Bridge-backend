import { Request, Response } from 'express';
import { AnalysisService } from '../services/analysis.service';
import { AgentService } from '../services/agent.service';

export class AnalysisController {
    private analysisService: AnalysisService;
    private agentService: AgentService;

    constructor() {
        this.analysisService = new AnalysisService();
        this.agentService = new AgentService();
    }

    /**
     * Analyze a new project description to extract skills, complexity, and timeline.
     */
    async analyzeProject(req: Request, res: Response) {
        try {
            const { projectId, description, budget, clientProposedTimeline } = req.body;

            if (!description) {
                return res.status(400).json({ status: 'error', message: 'Description is required' });
            }

            const result = await this.analysisService.analyzeProject({
                projectId,
                description,
                budget,
                clientProposedTimeline,
            });

            return res.status(200).json({ status: 'success', data: result });
        } catch (error) {
            console.error('Error in analyzeProject:', error);
            return res.status(500).json({ status: 'error', message: 'Internal server error' });
        }
    }
}
