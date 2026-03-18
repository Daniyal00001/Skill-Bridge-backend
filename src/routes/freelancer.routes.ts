import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { 
  getAllFreelancers, 
  getFreelancerById, 
  inviteFreelancer, 
  initiateChat 
} from '../controllers/freelancer.controller'

import {
  getMyFreelancerProfile,
  updateOnboardingStep1,
  updateOnboardingStep2,
  updateOnboardingStep3,
  updateOnboardingStep5,
  uploadOnboardingFiles,
  updateFreelancerProfile
} from '../controllers/freelancer-onboarding.controller'
import { upload } from '../middlewares/upload.middleware'

const router = Router()

/**
 * @route   GET /api/freelancers
 * @desc    Browse freelancers with filters and pagination
 * @access  Private
 */
router.get('/', protect, getAllFreelancers)

/**
 * @route   GET /api/freelancers/me
 * @desc    Get current user's freelancer profile
 * @access  Private
 */
router.get('/me', protect, getMyFreelancerProfile)

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

/**
 * @route   POST /api/freelancers/onboarding/step-X
 * @desc    Freelancer onboarding flows
 * @access  Private
 */
router.post('/onboarding/step-1', protect, updateOnboardingStep1)
router.post('/onboarding/step-2', protect, updateOnboardingStep2)
router.post('/onboarding/step-3', protect, updateOnboardingStep3)
router.post('/onboarding/step-5', protect, updateOnboardingStep5)

/**
 * @route   POST /api/freelancers/onboarding/upload
 * @desc    Upload ID and Profile Picture
 * @access  Private
 */
router.post('/onboarding/upload', protect, upload.fields([{ name: 'idDocument', maxCount: 1 }, { name: 'profileImage', maxCount: 1 }]), uploadOnboardingFiles)

/**
 * @route   PATCH /api/freelancers/profile
 * @desc    Edit existing freelancer profile (partial updates)
 * @access  Private
 */
router.patch('/profile', protect, updateFreelancerProfile)

export default router
