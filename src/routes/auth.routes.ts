import { Router } from 'express'
import {
  signup,
  refresh,
  login,
  logout,
  googleCallback,
  forgotPassword,
  resetPassword,
} from '../controllers/auth.controller'
import passport from '../config/passport'

const router = Router()

router.post('/signup', signup)
router.post('/refresh', refresh)
router.post('/login', login)
router.post('/logout', logout)
router.post('/forgot-password', forgotPassword)
router.post('/reset-password', resetPassword)

// Google OAuth
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  session: false,
}))

router.get('/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_failed`,
  }),
  googleCallback
)

export default router