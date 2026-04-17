import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { getMyTokenBalance, getMyTokenHistory, buyTokens, createTokenPaymentIntent, confirmTokenCardPurchase } from '../controllers/token.controller'

const router = Router()

// GET /api/tokens/balance — Current SkillToken balance
router.get('/balance', protect, requireRole('FREELANCER'), getMyTokenBalance)

// GET /api/tokens/history — Full transaction history (paginated)
router.get('/history', protect, requireRole('FREELANCER'), getMyTokenHistory)

// POST /api/tokens/buy — Buy SkillTokens using balance
router.post('/buy', protect, requireRole('FREELANCER'), buyTokens)

// POST /api/tokens/buy-with-card/intent — Create Stripe intent
router.post('/buy-with-card/intent', protect, requireRole('FREELANCER'), createTokenPaymentIntent)

// POST /api/tokens/buy-with-card/confirm — Confirm purchase after success
router.post('/buy-with-card/confirm', protect, requireRole('FREELANCER'), confirmTokenCardPurchase)

export default router
