import { Request, Response } from 'express';
import { NegotiationService } from '../services/negotiation.service';

export class NegotiationController {
    private negotiationService: NegotiationService;

    constructor() {
        this.negotiationService = new NegotiationService();
    }

    /**
     * Generate a context-aware negotiation message draft.
     */
    async generateNegotiationMessage(req: Request, res: Response) {
        try {
            const { projectId, clientId, freelancerId, recentMessagesContext } = req.body;

            if (!projectId || !clientId || !freelancerId) {
                return res.status(400).json({ status: 'error', message: 'Missing required IDs' });
            }

            const draft = await this.negotiationService.generateResponseDraft(
                projectId,
                clientId,
                freelancerId,
                recentMessagesContext || []
            );

            return res.status(200).json({ status: 'success', data: { draft } });
        } catch (error) {
            console.error('Error in generateNegotiationMessage:', error);
            return res.status(500).json({ status: 'error', message: 'Internal server error' });
        }
    }
}
