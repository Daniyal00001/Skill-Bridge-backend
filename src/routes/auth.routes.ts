import { Router } from 'express'
import { signup , refresh , login , logout} from '../controllers/auth.controller'

const router = Router()

// ── Auth Routes ───────────────────────────────────────────────
// POST /api/auth/signup
router.post('/signup', signup)
router.post('/refresh', refresh)
router.post('/login', login)
router.post('/logout', logout)

export default router