import { Router } from 'express'
import { signup } from '../controllers/auth.controller'

const router = Router()

// ── Auth Routes ───────────────────────────────────────────────
// POST /api/auth/signup
router.post('/signup', signup)

// these will be added soon:
// router.post('/login', login)
// router.post('/logout', logout)
// router.post('/refresh', refresh)

export default router