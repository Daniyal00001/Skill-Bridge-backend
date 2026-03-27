import { Router } from 'express'
import { getMyProfile, updateMyProfile } from '../controllers/client.controller'
import { protect, requireRole } from '../middlewares/auth.middleware'

const router = Router()

// All routes require the user to be authenticated and have the 'CLIENT' role
router.use(protect)
router.use(requireRole('CLIENT'))

router.get('/profile', getMyProfile)
router.put('/profile', updateMyProfile)

export default router
