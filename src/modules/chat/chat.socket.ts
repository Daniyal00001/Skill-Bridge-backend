import { Server as SocketIOServer, Socket } from "socket.io";
import { Server as HTTPServer } from "http";
import express from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../../config/prisma";
import {
  saveMessage,
  markMessagesAsRead,
  isUserRestricted,
  doesRoomBelongToUser,
  getUnreadRoomsCount,
} from "./chat.service";
import { MessageWithSender } from "./chat.types";
import * as notificationService from "../../services/notification.service";

// Track online users: userId → Set of socketIds
const onlineUsers = new Map<string, Set<string>>();
let io: SocketIOServer | null = null;

export const getIO = () => io;

// In-memory rate limiting for Socket.IO messages
interface RateLimit {
  count: number;
  resetAt: number;
}
const socketRateLimits = new Map<string, RateLimit>();

const getUserIdFromSocket = (socket: Socket): string | null => {
  try {
    const token =
      socket.handshake.auth?.token ||
      (socket.handshake.headers.authorization as string)?.split(" ")[1];
    if (!token) return null;
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      userId: string;
    };
    return decoded.userId;
  } catch {
    return null;
  }
};

export const initChatSocket = (
  httpServer: HTTPServer,
  app: express.Application,
) => {
  const ioInstance = new SocketIOServer(httpServer, {
    cors: {
      origin: [
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:3000",
      ],
      credentials: true,
    },
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  io = ioInstance;
  app.set("io", ioInstance);

  // ── Auth Middleware ────────────────────────────────────────────────────────
  ioInstance.use((socket, next) => {
    const userId = getUserIdFromSocket(socket);
    if (!userId) {
      return next(new Error("Authentication error"));
    }
    (socket as any).userId = userId;
    next();
  });

  ioInstance.on("connection", async (socket) => {
    const userId = (socket as any).userId as string;
    console.log(`[Socket] User connected: ${userId} (${socket.id})`);

    // Track online status
    if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
    onlineUsers.get(userId)!.add(socket.id);

    // Send the current list of online users to the newly connected user
    socket.emit("online_users", { userIds: Array.from(onlineUsers.keys()) });

    // Join personal room for cross-device/cross-room events
    socket.join(`user:${userId}`);

    // Update lastActiveAt
    await prisma.user
      .update({ where: { id: userId }, data: { lastActiveAt: new Date() } })
      .catch(() => {});

    // Auto-join all rooms the user belongs to
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { clientProfile: true, freelancerProfile: true },
      });
      if (user) {
        const clientProfileId = user.clientProfile?.id;
        const freelancerProfileId = user.freelancerProfile?.id;
        const whereClause: any = {
          OR: [
            clientProfileId ? { clientProfileId } : undefined,
            freelancerProfileId ? { freelancerProfileId } : undefined,
          ].filter(Boolean),
        };
        const rooms = await prisma.chatRoom.findMany({ where: whereClause });
        for (const room of rooms) {
          socket.join(room.id);
          console.log(`[Socket] ${userId} joined room ${room.id}`);
        }
      }
    } catch (err) {
      console.error("[Socket] Failed to auto-join rooms:", err);
    }

    // Broadcast online status to all connected sockets
    ioInstance.emit("user_online", { userId, isOnline: true });

    // ── Event: join_room ────────────────────────────────────────────────────
    socket.on("join_room", async ({ roomId }: { roomId: string }) => {
      const belongs = await doesRoomBelongToUser(roomId, userId);
      if (!belongs) return;
      socket.join(roomId);
      console.log(`[Socket] ${userId} joined room ${roomId}`);
    });

    // ── Event: send_message ─────────────────────────────────────────────────
    socket.on(
      "send_message",
      async (data: { roomId: string; content: string; type?: string }) => {
        // 1. Rate Limiting (20 messages in 10 seconds)
        const now = Date.now();
        const limit = socketRateLimits.get(userId) || {
          count: 0,
          resetAt: now + 10000,
        };

        if (now > limit.resetAt) {
          limit.count = 0;
          limit.resetAt = now + 10000;
        }

        limit.count++;
        socketRateLimits.set(userId, limit);

        if (limit.count > 20) {
          return socket.emit("error", {
            message: "Too many messages sent. Please wait a few seconds.",
            rateLimitReached: true,
          });
        }

        // 2. Length Validation (Max 2000 chars)
        if (data.content && data.content.length > 2000) {
          return socket.emit("error", {
            message: "Message is too long (max 2000 characters)",
          });
        }

        try {
          const { roomId, content, type } = data;

          const belongs = await doesRoomBelongToUser(roomId, userId);
          if (!belongs)
            return socket.emit("error", { message: "Access denied" });

          const restricted = await isUserRestricted(roomId, userId);
          if (restricted)
            return socket.emit("error", {
              message: "You are restricted from this chat.",
            });

          const message = await saveMessage({
            chatRoomId: roomId,
            senderId: userId,
            content,
            type: (type as any) ?? "TEXT",
          });

          // 1. Broadcast to everyone currently in the socket room
          ioInstance.to(roomId).emit("new_message", message);

          // 2. Also emit to the recipient's personal room to ensure discovery
          const room = await prisma.chatRoom.findUnique({
            where: { id: roomId },
            include: {
              clientProfile: { select: { userId: true } },
              freelancerProfile: { select: { userId: true } },
            },
          });

          if (room) {
            let recipientId: string | null = null;
            if (room.clientProfile?.userId === userId) {
              recipientId = room.freelancerProfile?.userId || null;
            } else if (room.freelancerProfile?.userId === userId) {
              recipientId = room.clientProfile?.userId || null;
            }

            if (recipientId) {
              ioInstance.to(`user:${recipientId}`).emit("new_message", message);

              // 3. Update recipient's unread count badge
              const unreadCount = await getUnreadRoomsCount(recipientId);
              ioInstance
                .to(`user:${recipientId}`)
                .emit("unread_count_update", { count: unreadCount });

              // 4. Send a persistent feed notification (throttled to once per hour)
              const oneHourAgo = new Date(Date.now() - 1000 * 60 * 60);
              const existingRecent = await prisma.notification.findFirst({
                where: {
                  userId: recipientId,
                  type: "MESSAGE_RECEIVED",
                  createdAt: { gte: oneHourAgo },
                },
              });

              if (!existingRecent) {
                await notificationService.createNotification({
                  userId: recipientId,
                  type: "MESSAGE_RECEIVED",
                  title: "💬 New Message",
                  body: `You have new messages in your inbox from ${message.sender.name || "a user"}.`,
                  link: `/chat/${roomId}`,
                });
              }
            }
          }

          console.log(`[Socket] Message sent in room ${roomId} by ${userId}`);
        } catch (err) {
          console.error("[Socket] send_message error:", err);
          socket.emit("error", { message: "Failed to send message" });
        }
      },
    );

    // ── Event: typing_start ─────────────────────────────────────────────────
    socket.on(
      "typing_start",
      ({ roomId, userName }: { roomId: string; userName: string }) => {
        socket.to(roomId).emit("typing_start", { userId, userName, roomId });
      },
    );

    // ── Event: typing_stop ──────────────────────────────────────────────────
    socket.on("typing_stop", ({ roomId }: { roomId: string }) => {
      socket.to(roomId).emit("typing_stop", { userId, roomId });
    });

    // ── Event: mark_seen ────────────────────────────────────────────────────
    socket.on("mark_seen", async ({ roomId }: { roomId: string }) => {
      try {
        await markMessagesAsRead(roomId, userId);
        // Notify everyone in the active room
        ioInstance
          .to(roomId)
          .emit("messages_seen", {
            roomId,
            seenByUserId: userId,
            seenAt: new Date(),
          });

        // Also explicitly notify the other user in their personal channel
        const room = await prisma.chatRoom.findUnique({
          where: { id: roomId },
          include: {
            clientProfile: { select: { userId: true } },
            freelancerProfile: { select: { userId: true } },
          },
        });

        if (room) {
          let otherUserId: string | null = null;
          if (room.clientProfile?.userId === userId) {
            otherUserId = room.freelancerProfile?.userId || null;
          } else if (room.freelancerProfile?.userId === userId) {
            otherUserId = room.clientProfile?.userId || null;
          }

          if (otherUserId) {
            ioInstance
              .to(`user:${otherUserId}`)
              .emit("messages_seen", {
                roomId,
                seenByUserId: userId,
                seenAt: new Date(),
              });
          }
        }

        // Also update the current user's unread count
        const unreadCount = await getUnreadRoomsCount(userId);
        ioInstance
          .to(`user:${userId}`)
          .emit("unread_count_update", { count: unreadCount });
      } catch (err) {
        console.error("[Socket] mark_seen error:", err);
      }
    });

    // ── Event: disconnect ───────────────────────────────────────────────────
    socket.on("disconnect", async () => {
      console.log(`[Socket] User disconnected: ${userId} (${socket.id})`);

      const sockets = onlineUsers.get(userId);
      if (sockets) {
        sockets.delete(socket.id);
        if (sockets.size === 0) {
          onlineUsers.delete(userId);
          // Update lastActiveAt
          await prisma.user
            .update({
              where: { id: userId },
              data: { lastActiveAt: new Date() },
            })
            .catch(() => {});
          // Broadcast offline status
          ioInstance.emit("user_offline", {
            userId,
            isOnline: false,
            lastActiveAt: new Date(),
          });
        }
      }
    });
  });

  return ioInstance;
};

export const isUserOnline = (userId: string): boolean => {
  return onlineUsers.has(userId) && onlineUsers.get(userId)!.size > 0;
};
