import { Request, Response } from 'express'
import * as notificationService from '../services/notification.service'

export const getMyNotifications = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    // Find all unread notifications
    const unreadNotifications = await notificationService.getNotificationsForUser(userId, 500, 0, false)
    
    let notificationsToReturn = unreadNotifications;

    if (unreadNotifications.length === 0) {
      // If no unread, show last 10 read
      notificationsToReturn = await notificationService.getNotificationsForUser(userId, 10, 0, true)
    }

    const unreadCount = unreadNotifications.length;

    return res.status(200).json({
      success: true,
      notifications: notificationsToReturn,
      unreadCount
    })
  } catch (error) {
    console.error('[NotificationController] Error fetching notifications:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}


export const markAsRead = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params

    await notificationService.markAsRead(id, userId)

    return res.status(200).json({
      success: true,
      message: 'Notification marked as read.',
    })
  } catch (error) {
    console.error('[NotificationController] Error marking as read:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

export const markAllAsRead = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    await notificationService.markAllAsRead(userId)

    return res.status(200).json({
      success: true,
      message: 'All notifications marked as read.',
    })
  } catch (error) {
    console.error('[NotificationController] Error marking all as read:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

export const deleteNotification = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params

    await notificationService.deleteNotification(id, userId)

    return res.status(200).json({
      success: true,
      message: 'Notification deleted.',
    })
  } catch (error) {
    console.error('[NotificationController] Error deleting notification:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
