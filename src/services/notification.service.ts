import { prisma } from '../config/prisma'
import { getIO } from '../modules/chat/chat.socket'
import { NotificationType } from '@prisma/client'

export interface CreateNotificationPayload {
  userId: string
  type: NotificationType
  title: string
  body: string
  link?: string
}


const getPreferenceField = (type: NotificationType): string => {
  switch (type) {
    case 'MESSAGE_RECEIVED':
      return 'messageNotifications';
    case 'PROPOSAL_RECEIVED':
    case 'PROPOSAL_ACCEPTED':
    case 'PROPOSAL_REJECTED':
    case 'PROPOSAL_SHORTLISTED':
    case 'PROJECT_STARTED':
    case 'MILESTONE_SUBMITTED':
    case 'MILESTONE_APPROVED':
    case 'INVITATION_RECEIVED':
      return 'projectNotifications';
    default:
      return 'accountNotifications';
  }
};

export const createNotification = async (payload: CreateNotificationPayload, tx?: any) => {
  try {
    const client = tx || prisma
    
    // ── 1. Fetch User (needed for preferences AND role-based links) ─────────────────
    const user = await client.user.findUnique({
      where: { id: payload.userId },
      select: {
        role: true,
        projectNotifications: true,
        messageNotifications: true,
        accountNotifications: true,
      }
    });

    if (!user) return null;

    // ── 2. Check Preferences ───────────────────────────────
    const prefField = getPreferenceField(payload.type);
    const isEnabled = (user as any)[prefField] ?? true;
    
    if (!isEnabled) {
      console.log(`[NotificationService] Skipping notification ${payload.type} for ${payload.userId} (disabled).`);
      return null;
    }

    // ── 3. Transform Link based on Type & Role ───────────────────────────────────
    let finalLink = payload.link;

    // A) Handle Message Redirection
    if (payload.type === 'MESSAGE_RECEIVED' && finalLink?.includes('/chat/')) {
      const roomId = finalLink.split('/').pop();
      const base = user.role === 'FREELANCER' ? '/freelancer' : '/client';
      finalLink = `${base}/messages?room=${roomId}`;
    }

    // B) Handle Dispute Redirection
    if (['DISPUTE_OPENED', 'DISPUTE_RESOLVED'].includes(payload.type)) {
      if (user.role === 'ADMIN') {
        // Admins go to the admin dispute detail if link contains ID
        const disputeId = finalLink?.split('/').pop();
        finalLink = disputeId && disputeId.length > 10 ? `/admin/disputes/${disputeId}` : '/admin/disputes';
      } else {
        const base = user.role === 'FREELANCER' ? '/freelancer' : '/client';
        finalLink = `${base}/contracts?tab=disputed`;
      }
    }

    // ── 4. Create in Database ─────────────────────────────
    const notification = await client.notification.create({
      data: {
        userId: payload.userId,
        type: payload.type,
        title: payload.title,
        body: payload.body,
        link: finalLink || null,
      },
    })

    // Emit real-time event via Socket.IO
    const io = getIO()
    if (io) {
      io.to(`user:${payload.userId}`).emit('new_notification', notification)
      
      const unreadCount = await client.notification.count({
        where: { userId: payload.userId, isRead: false }
      })
      io.to(`user:${payload.userId}`).emit('unread_notifications_count', { count: unreadCount })
    }

    return notification
  } catch (error) {
    console.error('[NotificationService] Error creating notification:', error)
    return null
  }
}

export const getNotificationsForUser = async (userId: string, limit = 50, offset = 0, isRead?: boolean) => {
  return prisma.notification.findMany({
    where: { 
      userId,
      ...(isRead !== undefined ? { isRead } : {})
    },
    orderBy: { createdAt: 'desc' },
    take: limit,
    skip: offset,
  })
}

export const markAsRead = async (notificationId: string, userId: string) => {
  const result = await prisma.notification.updateMany({
    where: { id: notificationId, userId },
    data: { isRead: true },
  })
  console.log(`[NotificationService] MarkAsRead result for notification ${notificationId}:`, result)
  return result
}

export const markAllAsRead = async (userId: string) => {
  return prisma.notification.updateMany({
    where: { userId, isRead: false },
    data: { isRead: true },
  })
}

export const deleteNotification = async (notificationId: string, userId: string) => {
  return prisma.notification.deleteMany({
    where: { id: notificationId, userId },
  })
}
