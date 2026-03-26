// ── Chat Module Types ───────────────────────────────────────────────────────

export interface ChatRoomWithParticipants {
  id: string
  contractId: string | null
  projectId: string | null
  clientProfileId: string | null
  freelancerProfileId: string | null
  createdAt: Date
  lastMessage?: MessageWithSender | null
  unreadCount?: number
  otherUser?: {
    id: string
    name: string
    avatar: string | null
    role: string
    isOnline?: boolean
    lastActiveAt?: Date | null
  }
  isMuted?: boolean
  isRestricted?: boolean
}

export interface MessageWithSender {
  id: string
  chatRoomId: string
  senderId: string
  content: string
  type: 'TEXT' | 'FILE' | 'SYSTEM'
  fileUrl: string | null
  fileName?: string | null
  fileSize?: number | null
  fileMimeType?: string | null
  isRead: boolean
  sentAt: Date
  sender: {
    id: string
    name: string
    profileImage: string | null
    role: string | null
  }
}

export interface SendMessagePayload {
  chatRoomId: string
  senderId: string
  content: string
  type?: 'TEXT' | 'FILE' | 'SYSTEM'
  fileUrl?: string
  fileName?: string
  fileSize?: number
  fileMimeType?: string
}

export interface TypingPayload {
  roomId: string
  userId: string
  userName: string
  isTyping: boolean
}

export interface SeenPayload {
  roomId: string
  userId: string
  lastSeenMessageId: string
}

export interface OnlineStatusPayload {
  userId: string
  isOnline: boolean
  lastActiveAt?: Date
}

export interface PaginatedMessages {
  messages: MessageWithSender[]
  nextCursor: string | null
  hasMore: boolean
}
