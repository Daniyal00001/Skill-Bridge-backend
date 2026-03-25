import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import {
  getInvitations,
  cancelInvitation,
  acceptInvitation,
  rejectInvitation
} from '../controllers/invitation.controller'

const router = Router()

/**
 * @route   GET /api/invitations
 * @desc    Get all invitations for authenticated user
 * @access  Private
 */
router.get('/', protect, getInvitations)

/**
 * @route   PATCH /api/invitations/:id/cancel
 * @desc    Cancel a pending invitation
 * @access  Private (CLIENT)
 */
router.patch('/:id/cancel', protect, requireRole('CLIENT'), cancelInvitation)

/**
 * @route   PATCH /api/invitations/:id/accept
 * @desc    Accept an invitation (Creates Contract)
 * @access  Private (FREELANCER)
 */
router.patch('/:id/accept', protect, requireRole('FREELANCER'), acceptInvitation)

/**
 * @route   PATCH /api/invitations/:id/reject
 * @desc    Reject an invitation
 * @access  Private (FREELANCER)
 */
router.patch('/:id/reject', protect, requireRole('FREELANCER'), rejectInvitation)

export default router
