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
  requestWithdrawal,
  createFreelancerSetupIntent,
  getFreelancerPaymentMethods,
  deleteFreelancerPaymentMethod,
} from '../controllers/stripe.controller'

const router = Router()

// ── Client: Fund Milestones ────────────────────────────────────────────────
router.post('/create-payment-intent', protect, requireRole('CLIENT'), createPaymentIntent)
router.post('/confirm-fund', protect, requireRole('CLIENT'), confirmFundMilestone)

// ── Freelancer: Connect Onboarding (Payouts) ──────────────────────────────
router.get('/setup-payouts', protect, requireRole('FREELANCER'), setupFreelancerPayouts)
router.get('/onboarding-status', protect, requireRole('FREELANCER'), checkOnboardingStatus)

// ── Freelancer: Earnings & Withdrawals ────────────────────────────────────
router.get('/freelancer/balance', protect, requireRole('FREELANCER'), getFreelancerBalance)
router.post('/freelancer/withdraw', protect, requireRole('FREELANCER'), requestWithdrawal)

// ── Freelancer: Saved Cards (for token purchases) ─────────────────────────
// NOTE: completely separate from client billing and from Stripe Connect payouts
router.post('/freelancer/setup-intent', protect, requireRole('FREELANCER'), createFreelancerSetupIntent)
router.get('/freelancer/payment-methods', protect, requireRole('FREELANCER'), getFreelancerPaymentMethods)
router.delete('/freelancer/payment-methods/:methodId', protect, requireRole('FREELANCER'), deleteFreelancerPaymentMethod)

// ── Client: Saved Cards (for funding milestones) ──────────────────────────
router.post('/create-setup-intent', protect, requireRole('CLIENT'), createSetupIntent)
router.get('/payment-methods', protect, requireRole('CLIENT'), getPaymentMethods)
router.delete('/payment-methods/:methodId', protect, requireRole('CLIENT'), deletePaymentMethod)

export default router
