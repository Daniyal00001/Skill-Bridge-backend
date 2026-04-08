import { Router } from 'express'
import {
  getMyProfile,
  updateMyProfile,
  requestEmailChange,
  verifyEmailChange,
  requestPhoneOtp,
  verifyPhoneOtp,
  uploadIdDocument,
} from '../controllers/client.controller'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { upload } from '../middlewares/upload.middleware'

const router = Router()

router.use(protect)
router.use(requireRole('CLIENT'))

router.get('/profile', getMyProfile)
router.put('/profile', updateMyProfile)

// Email change with OTP
router.post('/profile/request-email-change', requestEmailChange)
router.post('/profile/verify-email-change', verifyEmailChange)

// Phone verification with OTP (WhatsApp placeholder)
router.post('/profile/request-phone-otp', requestPhoneOtp)
router.post('/profile/verify-phone-otp', verifyPhoneOtp)

// Upload ID document
router.post('/profile/upload-id', upload.fields([{ name: 'idDocument', maxCount: 1 }]), uploadIdDocument)

export default router
