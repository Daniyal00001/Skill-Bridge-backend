import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { getMyProposals } from '../controllers/proposal.controller'

const router = Router()

/**
 * @route   GET /api/proposals/my
 * @desc    Get all proposals submitted by the logged-in freelancer
 * @access  Private (FREELANCER only)
 */
router.get('/my', protect, requireRole('FREELANCER'), getMyProposals)

export default router
