import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { getMyTokenBalance, getMyTokenHistory } from '../controllers/token.controller'

const router = Router()

// GET /api/tokens/balance — Current SkillToken balance
router.get('/balance', protect, requireRole('FREELANCER'), getMyTokenBalance)

// GET /api/tokens/history — Full transaction history (paginated)
router.get('/history', protect, requireRole('FREELANCER'), getMyTokenHistory)

export default router
