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

export const createNotification = async (payload: CreateNotificationPayload, tx?: any) => {
  try {
    const client = tx || prisma
    const notification = await client.notification.create({
      data: {
        userId: payload.userId,
        type: payload.type,
        title: payload.title,
        body: payload.body,
        link: payload.link || null,
      },
    })

    // Emit real-time event via Socket.IO
    const io = getIO()
    if (io) {
      io.to(`user:${payload.userId}`).emit('new_notification', notification)
      
      // Also emit a count update if needed (though the frontend can just increment locally)
      const unreadCount = await client.notification.count({
        where: { userId: payload.userId, isRead: false }
      })
      io.to(`user:${payload.userId}`).emit('unread_notifications_count', { count: unreadCount })
    }

    return notification
  } catch (error) {
    console.error('[NotificationService] Error creating notification:', error)
    // We don't want to crash the main flow if notification fails, 
    // but maybe we should throw in some cases? For now, just log.
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
  return prisma.notification.updateMany({
    where: { id: notificationId, userId },
    data: { isRead: true },
  })
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
