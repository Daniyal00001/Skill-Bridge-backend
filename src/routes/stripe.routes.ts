import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { 
  createPaymentIntent, 
  confirmFundMilestone,
  setupFreelancerPayouts,
  checkOnboardingStatus,
  createSetupIntent,
  getPaymentMethods,
  deletePaymentMethod,
  getFreelancerBalance,
  requestWithdrawal
} from '../controllers/stripe.controller'

const router = Router()

// Create a Stripe PaymentIntent for a milestone (Client only)
router.post('/create-payment-intent', protect, requireRole('CLIENT'), createPaymentIntent)

// After Stripe payment succeeds on frontend, confirm and fund the milestone
router.post('/confirm-fund', protect, requireRole('CLIENT'), confirmFundMilestone)

// Freelancer Connect Onboarding
router.get('/setup-payouts', protect, requireRole('FREELANCER'), setupFreelancerPayouts)
router.get('/onboarding-status', protect, requireRole('FREELANCER'), checkOnboardingStatus)

// Freelancer Balance & Withdrawals
router.get('/freelancer/balance', protect, requireRole('FREELANCER'), getFreelancerBalance)
router.post('/freelancer/withdraw', protect, requireRole('FREELANCER'), requestWithdrawal)

// Client Payment Methods
router.post('/create-setup-intent', protect, requireRole('CLIENT'), createSetupIntent)
router.get('/payment-methods', protect, requireRole('CLIENT'), getPaymentMethods)
router.delete('/payment-methods/:methodId', protect, requireRole('CLIENT'), deletePaymentMethod)

export default router
