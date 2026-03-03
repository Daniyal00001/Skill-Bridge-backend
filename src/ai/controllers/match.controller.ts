import { Request, Response } from 'express';
import { MatchingService } from '../services/matching.service';

export class MatchController {
    private matchingService: MatchingService;

    constructor() {
        this.matchingService = new MatchingService();
    }

    /**
     * Find top 10 matched freelancers for a project description.
     */
    async matchFreelancers(req: Request, res: Response) {
        try {
            const { projectDescription, extractedSkills } = req.body;

            if (!projectDescription) {
                return res.status(400).json({ status: 'error', message: 'projectDescription is required' });
            }

            const matches = await this.matchingService.findMatches(projectDescription, extractedSkills || []);

            return res.status(200).json({ status: 'success', data: { matches } });
        } catch (error) {
            console.error('Error in matchFreelancers:', error);
            return res.status(500).json({ status: 'error', message: 'Internal server error' });
        }
    }
}
