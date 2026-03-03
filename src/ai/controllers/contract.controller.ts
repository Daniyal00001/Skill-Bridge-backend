import { Request, Response } from 'express';
import { ContractService } from '../services/contract.service';

export class ContractController {
    private contractService: ContractService;

    constructor() {
        this.contractService = new ContractService();
    }

    /**
     * Generate a structured freelance contract draft.
     */
    async generateContractDraft(req: Request, res: Response) {
        try {
            const { projectDetails, agreedTerms, milestones, paymentTerms } = req.body;

            if (!projectDetails || !agreedTerms) {
                return res.status(400).json({ status: 'error', message: 'projectDetails and agreedTerms are required' });
            }

            const contractDraft = await this.contractService.generateContractDraft({
                projectDetails,
                agreedTerms,
                milestones,
                paymentTerms,
            });

            return res.status(200).json({ status: 'success', data: { contractDraft } });
        } catch (error) {
            console.error('Error in generateContractDraft:', error);
            return res.status(500).json({ status: 'error', message: 'Internal server error' });
        }
    }
}
