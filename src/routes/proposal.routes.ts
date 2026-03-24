import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { upload } from '../middlewares/upload.middleware'
import {
  submitProposal,
  getMyProposals,
  getProjectProposals,
  updateProposalStatus,
  withdrawProposal,
  getProjectTokenCost,
  proposeMilestoneChanges,
  acceptMilestoneChanges,
  requestRevisionChanges,
  getProposal,
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
  upload.array('files', 5),
  submitProposal
)

// Get all proposals submitted by the logged-in freelancer
router.get('/my', protect, requireRole('FREELANCER'), getMyProposals)

// Withdraw a proposal (refunds tokens if PENDING or SHORTLISTED)
router.delete('/:id/withdraw', protect, requireRole('FREELANCER'), withdrawProposal)

// Get a single proposal detail (Client or Freelancer)
router.get('/:id', protect, getProposal)

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

// Propose milestone changes (Negotiate)
router.post('/:id/negotiate', protect, requireRole('CLIENT'), proposeMilestoneChanges)

// Request revision-only changes (Client — no milestones needed)
router.post('/:id/request-revisions', protect, requireRole('CLIENT'), requestRevisionChanges)

// Accept milestone/revision changes
router.post('/:id/accept-changes', protect, requireRole('FREELANCER'), acceptMilestoneChanges)

export default router
