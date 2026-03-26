import { Request, Response } from 'express'
import {
  getChatRoomsForUser,
  getOrCreateChatRoom,
  getPaginatedMessages,
  saveMessage,
  markMessagesAsRead,
  muteRoom,
  restrictUser,
  isUserRestricted,
  doesRoomBelongToUser,
  deleteChatRoom,
} from './chat.service'
import { sendMessageSchema, openRoomSchema, muteRoomSchema, restrictUserSchema } from './chat.schema'
import { uploadToCloudinary } from '../../utils/uploadToCloudinary'
import { prisma } from '../../config/prisma'

// ── GET /api/chat/rooms ───────────────────────────────────────────────────────
export const getRooms = async (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId
    const rooms = await getChatRoomsForUser(userId)
    res.json({ success: true, data: rooms })
  } catch (err) {
    console.error('[Chat] getRooms error:', err)
    res.status(500).json({ success: false, message: 'Failed to fetch rooms' })
  }
}

// ── POST /api/chat/rooms ──────────────────────────────────────────────────────
export const openRoom = async (req: Request, res: Response) => {
  try {
    const parsed = openRoomSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ success: false, message: parsed.error.errors[0].message })
    }
    const { clientProfileId, freelancerProfileId, contractId, projectId } = parsed.data
    const room = await getOrCreateChatRoom(clientProfileId, freelancerProfileId, contractId, projectId)
    res.json({ success: true, data: room })
  } catch (err) {
    console.error('[Chat] openRoom error:', err)
    res.status(500).json({ success: false, message: 'Failed to open chat room' })
  }
}

// ── GET /api/chat/rooms/:roomId/messages ──────────────────────────────────────
export const getMessages = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId
    const cursor = req.query.cursor as string | undefined

    const belongs = await doesRoomBelongToUser(roomId, userId)
    if (!belongs) return res.status(403).json({ success: false, message: 'Access denied' })

    const data = await getPaginatedMessages(roomId, cursor, 30)
    // Mark messages as read when fetched
    await markMessagesAsRead(roomId, userId)

    res.json({ success: true, data })
  } catch (err) {
    console.error('[Chat] getMessages error:', err)
    res.status(500).json({ success: false, message: 'Failed to fetch messages' })
  }
}

// ── POST /api/chat/rooms/:roomId/messages ─────────────────────────────────────
export const sendMessage = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId

    const belongs = await doesRoomBelongToUser(roomId, userId)
    if (!belongs) return res.status(403).json({ success: false, message: 'Access denied' })

    const restricted = await isUserRestricted(roomId, userId)
    if (restricted) return res.status(403).json({ success: false, message: 'You have been restricted from this chat.' })

    const parsed = sendMessageSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ success: false, message: parsed.error.errors[0].message })
    }

    const message = await saveMessage({
      chatRoomId: roomId,
      senderId: userId,
      content: parsed.data.content,
      type: parsed.data.type,
    })

    res.json({ success: true, data: message })
  } catch (err) {
    console.error('[Chat] sendMessage error:', err)
    res.status(500).json({ success: false, message: 'Failed to send message' })
  }
}

// ── POST /api/chat/rooms/:roomId/attachments ──────────────────────────────────
export const uploadAttachment = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId
    const files = req.files as Express.Multer.File[]

    if (!files || files.length === 0) {
      return res.status(400).json({ success: false, message: 'No files provided' })
    }

    const belongs = await doesRoomBelongToUser(roomId, userId)
    if (!belongs) return res.status(403).json({ success: false, message: 'Access denied' })

    const restricted = await isUserRestricted(roomId, userId)
    if (restricted) return res.status(403).json({ success: false, message: 'You have been restricted from this chat.' })

    const savedMessages = []
    for (const file of files) {
      // Upload with chat_attachments folder
      const publicId = `chat_attachments/${Date.now()}_${file.originalname}`
      let resourceType: 'image' | 'raw' | 'auto' = 'auto'
      if (file.mimetype.startsWith('image/')) resourceType = 'image'
      else resourceType = 'raw'

      const fileUrl = await uploadToCloudinary(file.buffer, file.originalname, file.mimetype)
      const content = file.originalname // use filename as content for FILE type messages

      const message = await saveMessage({
        chatRoomId: roomId,
        senderId: userId,
        content,
        type: 'FILE',
        fileUrl,
        fileName: file.originalname,
        fileSize: file.size,
        fileMimeType: file.mimetype,
      })
      savedMessages.push(message)
    }

    res.json({ success: true, data: savedMessages })
  } catch (err) {
    console.error('[Chat] uploadAttachment error:', err)
    res.status(500).json({ success: false, message: 'File upload failed' })
  }
}

// ── PATCH /api/chat/rooms/:roomId/mute ───────────────────────────────────────
export const muteRoomHandler = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId

    const parsed = muteRoomSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ success: false, message: 'Invalid request' })

    await muteRoom(userId, roomId, parsed.data.muted)
    res.json({ success: true, message: parsed.data.muted ? 'Room muted' : 'Room unmuted' })
  } catch (err) {
    console.error('[Chat] muteRoom error:', err)
    res.status(500).json({ success: false, message: 'Failed to update mute status' })
  }
}

// ── PATCH /api/chat/rooms/:roomId/restrict ────────────────────────────────────
export const restrictUserHandler = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId

    const parsed = restrictUserSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ success: false, message: 'Invalid request' })

    // Only room owner (client profile) can restrict
    const belongs = await doesRoomBelongToUser(roomId, userId)
    if (!belongs) return res.status(403).json({ success: false, message: 'Access denied' })

    await restrictUser(roomId, parsed.data.targetUserId, parsed.data.restricted)
    res.json({
      success: true,
      message: parsed.data.restricted ? 'User restricted' : 'User unrestricted',
    })
  } catch (err) {
    console.error('[Chat] restrictUser error:', err)
    res.status(500).json({ success: false, message: 'Failed to update restriction' })
  }
}

// ── POST /api/chat/rooms/:roomId/seen ─────────────────────────────────────────
export const markSeenHandler = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId
    await markMessagesAsRead(roomId, userId)
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to mark seen' })
  }
}
// ── DELETE /api/chat/rooms/:roomId ──────────────────────────────────────────
export const deleteRoom = async (req: Request, res: Response) => {
  try {
    const { roomId } = req.params
    const userId = req.user!.userId

    await deleteChatRoom(roomId, userId)
    res.json({ success: true, message: 'Chat deleted successfully' })
  } catch (err: any) {
    console.error('[Chat] deleteRoom error:', err)
    res.status(err.message === 'Access denied' ? 403 : 500).json({
      success: false,
      message: err.message || 'Failed to delete room',
    })
  }
}
