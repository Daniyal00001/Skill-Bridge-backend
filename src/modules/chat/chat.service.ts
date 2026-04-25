import { prisma } from '../../config/prisma'
import redis from '../../config/redis'
export interface SendMessagePayload {
  chatRoomId: string
  senderId: string
  content: string
  type?: 'TEXT' | 'FILE' | 'SYSTEM'
  fileUrl?: string
  fileName?: string
  fileSize?: number
  fileMimeType?: string
  isAiMessage?: boolean
}

export interface MessageWithSender {
  id: string
  chatRoomId: string
  senderId: string
  content: string
  type: 'TEXT' | 'FILE' | 'SYSTEM'
  fileUrl?: string | null
  fileName?: string
  fileSize?: number
  fileMimeType?: string
  isRead: boolean
  isAiMessage?: boolean
  sentAt: Date
  sender: {
    id: string
    name: string
    profileImage?: string | null
    role?: string | null
  }
}

export interface PaginatedMessages {
  messages: MessageWithSender[]
  nextCursor: string | null
  hasMore: boolean
}

export interface ChatRoomWithParticipants {
  id: string
  contractId?: string | null
  projectId?: string | null
  clientProfileId?: string | null
  freelancerProfileId?: string | null
  isActiveAI?: boolean
  createdAt: Date
  lastMessage?: MessageWithSender | null
  unreadCount: number
  isMuted?: boolean
  otherUser?: {
    id: string
    name: string
    avatar?: string | null
    role: string
    lastActiveAt?: Date | null
  }
}

const MUTE_KEY = (userId: string, roomId: string) => `muted:${userId}:${roomId}`
const RESTRICT_KEY = (roomId: string, userId: string) => `restricted:${roomId}:${userId}`

// ── Room Operations ───────────────────────────────────────────────────────────

export const getOrCreateChatRoom = async (
  clientProfileId: string,
  freelancerProfileId: string,
  contractId?: string,
  projectId?: string
) => {
  // Check if room already exists
  const existing = await prisma.chatRoom.findFirst({
    where: { clientProfileId, freelancerProfileId },
  })
  if (existing) {
    // If it was soft-deleted, we might want to un-delete it if someone "opens" it again
    try {
      if ((existing as any).clientDeleted || (existing as any).freelancerDeleted) {
        await prisma.chatRoom.update({
          where: { id: existing.id },
          data: { clientDeleted: false, freelancerDeleted: false }
        })
      }
    } catch {}
    return existing
  }

  return prisma.chatRoom.create({
    data: {
      clientProfileId,
      freelancerProfileId,
      contractId: contractId ?? null,
      projectId: projectId ?? null,
    },
  })
}

export const getChatRoomsForUser = async (userId: string): Promise<ChatRoomWithParticipants[]> => {
  // Find the user's profile IDs
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      clientProfile: true,
      freelancerProfile: true,
    },
  })
  if (!user) return []

  const clientProfileId = user.clientProfile?.id
  const freelancerProfileId = user.freelancerProfile?.id

  const whereClause: any = {
    OR: [
      clientProfileId ? { clientProfileId, clientDeleted: false } : undefined,
      freelancerProfileId ? { freelancerProfileId, freelancerDeleted: false } : undefined,
    ].filter(Boolean),
  }

  const rooms = await prisma.chatRoom.findMany({
    where: whereClause,
    include: {
      clientProfile: {
        include: { user: true },
      },
      freelancerProfile: {
        include: { user: true },
      },
      messages: {
        orderBy: { sentAt: 'desc' },
        take: 1,
        include: {
          sender: { select: { id: true, name: true, profileImage: true, role: true } },
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  })

  const result: ChatRoomWithParticipants[] = []

  for (const room of rooms) {
    const isClient = clientProfileId && room.clientProfileId === clientProfileId
    let otherUser: ChatRoomWithParticipants['otherUser'] | undefined

    if (isClient && room.freelancerProfile) {
      const u = room.freelancerProfile.user
      otherUser = {
        id: u.id,
        name: u.name,
        avatar: u.profileImage,
        role: 'FREELANCER',
        lastActiveAt: u.lastActiveAt,
      }
    } else if (!isClient && room.clientProfile) {
      const u = room.clientProfile.user
      otherUser = {
        id: u.id,
        name: u.name,
        avatar: u.profileImage,
        role: 'CLIENT',
        lastActiveAt: u.lastActiveAt,
      }
    }

    const unreadCount = await prisma.message.count({
      where: {
        chatRoomId: room.id,
        isRead: false,
        senderId: { not: userId },
      },
    })

    const isMuted = !!(await redis.get(MUTE_KEY(userId, room.id)))

    const lastMsg = room.messages[0]
    const lastMessage: MessageWithSender | null = lastMsg
      ? {
          id: lastMsg.id,
          chatRoomId: lastMsg.chatRoomId,
          senderId: lastMsg.senderId,
          content: lastMsg.content,
          type: lastMsg.type as 'TEXT' | 'FILE' | 'SYSTEM',
          fileUrl: lastMsg.fileUrl,
          isRead: lastMsg.isRead,
          sentAt: lastMsg.sentAt,
          sender: lastMsg.sender as MessageWithSender['sender'],
        }
      : null

    result.push({
      id: room.id,
      contractId: room.contractId,
      projectId: room.projectId,
      clientProfileId: room.clientProfileId,
      freelancerProfileId: room.freelancerProfileId,
      createdAt: room.createdAt,
      lastMessage,
      unreadCount,
      otherUser,
      isMuted,
    })
  }

  // Sort by last message time (most recent first)
  result.sort((a, b) => {
    const aTime = a.lastMessage?.sentAt?.getTime() ?? a.createdAt.getTime()
    const bTime = b.lastMessage?.sentAt?.getTime() ?? b.createdAt.getTime()
    return bTime - aTime
  })

  // Deduplicate by otherUser.id (Keep only the latest room per user)
  const finalResult: ChatRoomWithParticipants[] = []
  const seenUsers = new Map<string, number>() // userId -> index in finalResult

  for (const item of result) {
    const otherId = item.otherUser?.id
    if (!otherId) {
      finalResult.push(item)
      continue
    }

    if (seenUsers.has(otherId)) {
      // If we've seen this user, we don't add the room, 
      // but we could optionally sum up the unreadCount if they are separate threads.
      // THE USER REQUEST: "one user should not come twice".
      const existingIdx = seenUsers.get(otherId)!
      finalResult[existingIdx].unreadCount += item.unreadCount
      continue
    }

    seenUsers.set(otherId, finalResult.length)
    finalResult.push(item)
  }

  return finalResult
}

export const getUnreadRoomsCount = async (userId: string): Promise<number> => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      clientProfile: { select: { id: true } },
      freelancerProfile: { select: { id: true } },
    },
  })
  if (!user) return 0

  const clientProfileId = user.clientProfile?.id
  const freelancerProfileId = user.freelancerProfile?.id

  // 1. Get all active rooms for this user
  const rooms = await prisma.chatRoom.findMany({
    where: {
      OR: [
        clientProfileId ? { clientProfileId, clientDeleted: false } : undefined,
        freelancerProfileId ? { freelancerProfileId, freelancerDeleted: false } : undefined,
      ].filter(Boolean) as any,
    },
    select: { id: true },
  })

  if (rooms.length === 0) return 0

  // 2. Count distinct chatRoomIds that have unread messages NOT from current user
  const unreadMessagesGroupByRoom = await prisma.message.groupBy({
    by: ['chatRoomId'],
    where: {
      chatRoomId: { in: rooms.map((r) => r.id) },
      isRead: false,
      senderId: { not: userId },
    },
  })

  return unreadMessagesGroupByRoom.length
}

// ── Message Operations ────────────────────────────────────────────────────────

export const getPaginatedMessages = async (
  roomId: string,
  cursor?: string,
  limit = 30
): Promise<PaginatedMessages> => {
  const messages = await prisma.message.findMany({
    where: { chatRoomId: roomId },
    orderBy: { sentAt: 'desc' },
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    include: {
      sender: { select: { id: true, name: true, profileImage: true, role: true } },
    },
  })

  const hasMore = messages.length > limit
  if (hasMore) messages.pop()
  messages.reverse()

  const formatted: MessageWithSender[] = messages.map((m) => ({
    id: m.id,
    chatRoomId: m.chatRoomId,
    senderId: m.senderId,
    content: m.content,
    type: m.type as 'TEXT' | 'FILE' | 'SYSTEM',
    fileUrl: m.fileUrl,
    isRead: m.isRead,
    sentAt: m.sentAt,
    sender: m.sender as MessageWithSender['sender'],
  }))

  const nextCursor = hasMore ? messages[0]?.id ?? null : null

  return { messages: formatted, nextCursor, hasMore }
}

import { sanitize, stripTags } from '../../utils/sanitize'

export const saveMessage = async (payload: SendMessagePayload): Promise<MessageWithSender> => {
  if (payload.content.length > 2000) {
    throw new Error('Message is too long (max 2000 characters)')
  }

  // Sanitize content: Strip ALL tags for TEXT, use safe allow-list for SYSTEM/others
  const sanitizedContent = (payload.type === 'TEXT' || !payload.type) 
    ? stripTags(payload.content) 
    : sanitize(payload.content)

  const message = await prisma.message.create({
    data: {
      chatRoomId: payload.chatRoomId,
      senderId: payload.senderId,
      content: sanitizedContent || '',
      type: (payload.type ?? 'TEXT') as any,
      fileUrl: payload.fileUrl ?? null,
      isAiMessage: payload.isAiMessage ?? false,
    },
    include: {
      sender: { select: { id: true, name: true, profileImage: true, role: true } },
    },
  })

  // Reset deletion flags so the conversation reappears for both
  try {
    await prisma.chatRoom.update({
      where: { id: payload.chatRoomId },
      data: { clientDeleted: false, freelancerDeleted: false }
    })
  } catch (err) {
    console.error('[Chat] soft-delete reset error:', err)
    // Non-blocking error
  }

  return {
    id: message.id,
    chatRoomId: message.chatRoomId,
    senderId: message.senderId,
    content: message.content,
    type: message.type as 'TEXT' | 'FILE' | 'SYSTEM',
    fileUrl: message.fileUrl,
    fileName: payload.fileName,
    fileSize: payload.fileSize,
    fileMimeType: payload.fileMimeType,
    isRead: message.isRead,
    isAiMessage: message.isAiMessage,
    sentAt: message.sentAt,
    sender: message.sender as MessageWithSender['sender'],
  }
}

export const markMessagesAsRead = async (roomId: string, userId: string): Promise<void> => {
  await prisma.message.updateMany({
    where: {
      chatRoomId: roomId,
      isRead: false,
      senderId: { not: userId },
    },
    data: { isRead: true },
  })
}

// ── Mute / Restrict ───────────────────────────────────────────────────────────

export const muteRoom = async (userId: string, roomId: string, muted: boolean): Promise<void> => {
  const key = MUTE_KEY(userId, roomId)
  if (muted) {
    await redis.setEx(key, 60 * 60 * 24 * 365, '1') // 1 year
  } else {
    await redis.del(key)
  }
}

export const isRoomMuted = async (userId: string, roomId: string): Promise<boolean> => {
  return !!(await redis.get(MUTE_KEY(userId, roomId)))
}

export const restrictUser = async (
  roomId: string,
  targetUserId: string,
  restricted: boolean
): Promise<void> => {
  const key = RESTRICT_KEY(roomId, targetUserId)
  if (restricted) {
    await redis.setEx(key, 60 * 60 * 24 * 365, '1')
  } else {
    await redis.del(key)
  }
}

export const isUserRestricted = async (roomId: string, userId: string): Promise<boolean> => {
  // 1. Check global ban status
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { isBanned: true }
  })
  if (user?.isBanned) return true

  // 2. Check room-specific restriction in Redis
  return !!(await redis.get(RESTRICT_KEY(roomId, userId)))
}

export const doesRoomBelongToUser = async (roomId: string, userId: string): Promise<boolean> => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { clientProfile: true, freelancerProfile: true },
  })
  if (!user) return false

  const room = await prisma.chatRoom.findUnique({ where: { id: roomId } })
  if (!room) return false

  return (
    (!!user.clientProfile && room.clientProfileId === user.clientProfile.id) ||
    (!!user.freelancerProfile && room.freelancerProfileId === user.freelancerProfile.id)
  )
}
export const deleteChatRoom = async (roomId: string, userId: string): Promise<void> => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { clientProfile: true, freelancerProfile: true },
  })
  if (!user) throw new Error('User not found')

  const room = await prisma.chatRoom.findUnique({ where: { id: roomId } })
  if (!room) throw new Error('Chat room not found')

  const isClient = !!user.clientProfile && room.clientProfileId === user.clientProfile.id
  const isFreelancer = !!user.freelancerProfile && room.freelancerProfileId === user.freelancerProfile.id

  if (!isClient && !isFreelancer) throw new Error('Access denied')

  if (isClient) {
    await prisma.chatRoom.update({ where: { id: roomId }, data: { clientDeleted: true } })
  } else {
    await prisma.chatRoom.update({ where: { id: roomId }, data: { freelancerDeleted: true } })
  }
}
