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
