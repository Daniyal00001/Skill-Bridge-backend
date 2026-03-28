import { Request, Response } from "express";
import * as notificationService from "../services/notification.service";
import { prisma } from "../config/prisma";

export const getMyNotifications = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;

    // Find last 100 notifications (both read and unread) for history
    const allNotifications = await notificationService.getNotificationsForUser(userId, 100, 0)
    
    // Get the total unread count for the red badge
    const unreadCount = await prisma.notification.count({
      where: { userId, isRead: false }
    })

    return res.status(200).json({
      success: true,
      notifications: allNotifications,
      unreadCount
    })
  } catch (error) {
    console.error(
      "[NotificationController] Error fetching notifications:",
      error,
    );
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

export const markAsRead = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { id } = req.params;

    console.log(
      `[NotificationController] markAsRead called for ID: ${id}, User: ${userId}`,
    );
    await notificationService.markAsRead(id, userId);

    return res.status(200).json({
      success: true,
      message: "Notification marked as read.",
    });
  } catch (error) {
    console.error("[NotificationController] Error marking as read:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

export const markAllAsRead = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;

    await notificationService.markAllAsRead(userId);

    return res.status(200).json({
      success: true,
      message: "All notifications marked as read.",
    });
  } catch (error) {
    console.error("[NotificationController] Error marking all as read:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

export const deleteNotification = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { id } = req.params;

    await notificationService.deleteNotification(id, userId);

    return res.status(200).json({
      success: true,
      message: "Notification deleted.",
    });
  } catch (error) {
    console.error(
      "[NotificationController] Error deleting notification:",
      error,
    );
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};
