import { Router } from 'express'
import { protect } from '../../middlewares/auth.middleware'
import { upload, largeUpload } from '../../middlewares/upload.middleware'
import {
  getRooms,
  openRoom,
  getMessages,
  sendMessage,
  uploadAttachment,
  muteRoomHandler,
  restrictUserHandler,
  markSeenHandler,
  deleteRoom,
  getUnreadCount,
} from './chat.controller'
import { contentFilterMiddleware } from '../../middlewares/content.filter.middleware'
import { messageRateLimiter } from '../../middlewares/rateLimit.middleware'

const router = Router()

// All chat routes require authentication
router.use(protect)

router.get('/unread-count', getUnreadCount)

// Room management
router.get('/rooms', getRooms)
router.post('/rooms', openRoom)
router.delete('/rooms/:roomId', deleteRoom)

// Messages (paginated via cursor query param)
router.get('/rooms/:roomId/messages', getMessages)
router.post('/rooms/:roomId/messages', messageRateLimiter, contentFilterMiddleware, sendMessage)

// Attachments (up to 5 files per request, 500MB total/each limit)
router.post('/rooms/:roomId/attachments', messageRateLimiter, contentFilterMiddleware, largeUpload.array('files', 5), uploadAttachment)


// Mark seen
router.post('/rooms/:roomId/seen', markSeenHandler)

// Mute / Restrict
router.patch('/rooms/:roomId/mute', muteRoomHandler)
router.patch('/rooms/:roomId/restrict', restrictUserHandler)

export default router
