import { Router } from 'express'
import { protect } from '../middlewares/auth.middleware'
import {
  getMyNotifications,
  markAsRead,
  markAllAsRead,
  deleteNotification
} from '../controllers/notification.controller'

const router = Router()

router.get('/', protect, getMyNotifications)
router.patch('/mark-all-read', protect, markAllAsRead)
router.patch('/:id/mark-read', protect, markAsRead)
router.delete('/:id', protect, deleteNotification)

export default router
