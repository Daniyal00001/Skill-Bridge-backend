import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { 
  createPaymentIntent, 
  confirmFundMilestone,
  setupFreelancerPayouts,
  checkOnboardingStatus,
  createSetupIntent,
  getPaymentMethods
} from '../controllers/stripe.controller'

const router = Router()

// Create a Stripe PaymentIntent for a milestone (Client only)
router.post('/create-payment-intent', protect, requireRole('CLIENT'), createPaymentIntent)

// After Stripe payment succeeds on frontend, confirm and fund the milestone
router.post('/confirm-fund', protect, requireRole('CLIENT'), confirmFundMilestone)

// Freelancer Connect Onboarding
router.get('/setup-payouts', protect, requireRole('FREELANCER'), setupFreelancerPayouts)
router.get('/onboarding-status', protect, requireRole('FREELANCER'), checkOnboardingStatus)

// Client Payment Methods
router.post('/create-setup-intent', protect, requireRole('CLIENT'), createSetupIntent)
router.get('/payment-methods', protect, requireRole('CLIENT'), getPaymentMethods)

export default router
