import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import {
  submitProposal,
  getMyProposals,
  getProjectProposals,
  updateProposalStatus,
  withdrawProposal,
  getProjectTokenCost,
} from '../controllers/proposal.controller'

const router = Router()

// ── Freelancer Routes ──────────────────────────────────────────────────────────

// Get token cost preview for a project (before submitting)
router.get(
  '/project/:projectId/token-cost',
  protect,
  requireRole('FREELANCER'),
  getProjectTokenCost
)

// Submit a proposal for a project
router.post(
  '/project/:projectId',
  protect,
  requireRole('FREELANCER'),
  submitProposal
)

// Get all proposals submitted by the logged-in freelancer
router.get('/my', protect, requireRole('FREELANCER'), getMyProposals)

// Withdraw a proposal (refunds tokens if PENDING or SHORTLISTED)
router.delete('/:id/withdraw', protect, requireRole('FREELANCER'), withdrawProposal)

// ── Client Routes ──────────────────────────────────────────────────────────────

// Get all proposals for a specific project
router.get(
  '/project/:projectId',
  protect,
  requireRole('CLIENT'),
  getProjectProposals
)

// Accept / Reject / Shortlist a proposal
router.patch(
  '/:id/status',
  protect,
  requireRole('CLIENT'),
  updateProposalStatus
)

export default router
