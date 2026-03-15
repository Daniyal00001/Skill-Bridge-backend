import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { 
  getAllFreelancers, 
  getFreelancerById, 
  inviteFreelancer, 
  initiateChat 
} from '../controllers/freelancer.controller'

const router = Router()

/**
 * @route   GET /api/freelancers
 * @desc    Browse freelancers with filters and pagination
 * @access  Private
 */
router.get('/', protect, getAllFreelancers)

/**
 * @route   GET /api/freelancers/:id
 * @desc    Get freelancer profile details
 * @access  Private
 */
router.get('/:id', protect, getFreelancerById)

/**
 * @route   POST /api/freelancers/:id/invite
 * @desc    Invite a freelancer to a project
 * @access  Private (CLIENT only)
 */
router.post('/:id/invite', protect, requireRole('CLIENT'), inviteFreelancer)

/**
 * @route   POST /api/freelancers/:id/message
 * @desc    Initiate or get chat room for recruitment
 * @access  Private (CLIENT only)
 */
router.post('/:id/message', protect, requireRole('CLIENT'), initiateChat)

export default router
