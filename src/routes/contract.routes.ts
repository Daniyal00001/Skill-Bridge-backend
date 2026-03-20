import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { upload } from '../middlewares/upload.middleware'
import {
  getContractByProject,
  getContractById,
  setContractMilestones,
  fundMilestone,
  startMilestone,
  submitMilestone,
  approveMilestone,
  requestRevision,
  getMyContracts,
  approveContractOffer,
  rejectContractOffer,
} from '../controllers/contract.controller'

const router = Router()

// Get all my contracts (General for both roles)
router.get('/', protect, getMyContracts)

// ── Shared (both roles) ─────────────────────────────────────────────────────────
router.get('/project/:projectId', protect, getContractByProject)
router.get('/:contractId', protect, getContractById)

// ── Client Routes ───────────────────────────────────────────────────────────────
// Set / replace milestones on a contract (before work starts)
router.post('/:contractId/milestones', protect, requireRole('CLIENT'), setContractMilestones)

// Fund a milestone (dummy escrow)
router.post('/:contractId/milestones/:milestoneId/fund', protect, requireRole('CLIENT'), fundMilestone)

// Approve milestone (releases payment)
router.post('/:contractId/milestones/:milestoneId/approve', protect, requireRole('CLIENT'), approveMilestone)

// Request revision
router.post('/:contractId/milestones/:milestoneId/revision', protect, requireRole('CLIENT'), requestRevision)

// ── Freelancer Routes ───────────────────────────────────────────────────────────
// Start a funded milestone
router.post('/:contractId/milestones/:milestoneId/start', protect, requireRole('FREELANCER'), startMilestone)

// Approve contract offer (for modified milestones)
router.patch('/:contractId/approve', protect, requireRole('FREELANCER'), approveContractOffer)

// Reject contract offer
router.delete('/:contractId/reject', protect, requireRole('FREELANCER'), rejectContractOffer)

// Submit deliverables
router.post(
  '/:contractId/milestones/:milestoneId/submit',
  protect,
  requireRole('FREELANCER'),
  upload.array('files', 5),
  submitMilestone
)

export default router
