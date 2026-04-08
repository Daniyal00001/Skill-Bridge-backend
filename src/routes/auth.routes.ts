import { Router } from 'express'
import {
  signup,
  verifyOtp,
  resendOtp,
  refresh,
  login,
  logout,
  googleCallback,
  forgotPassword,
  resetPassword,
  completeGoogleSignup,
  changePassword,
  updateNotificationSettings,
} from '../controllers/auth.controller'
import passport from '../config/passport'
import { protect } from '../middlewares/auth.middleware'

const router = Router()

router.post('/signup', signup)
router.post('/verify-otp', verifyOtp)
router.post('/resend-otp', resendOtp)
router.post('/refresh', refresh)
router.post('/login', login)
router.post('/logout', logout)
router.post('/forgot-password', forgotPassword)
router.post('/reset-password', resetPassword)
router.post('/complete-google-signup', protect, completeGoogleSignup)
router.put('/change-password', protect, changePassword)
router.put('/notification-settings', protect, updateNotificationSettings)

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