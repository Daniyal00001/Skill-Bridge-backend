import { Router, Request, Response } from 'express';
import axios from 'axios';
import { prisma } from '../config/prisma';

const router = Router();
const getPythonUrl = () => {
  const url = process.env.PYTHON_AI_URL || process.env.AI_BACKEND_URL || 'http://localhost:8000/api';
  return url.replace(/\/$/, '');
};

// Helper for proxy errors
const handleProxyError = (tag: string, error: any, res: Response, defaultMsg: string) => {
  const pythonUrl = getPythonUrl();
  console.error(`❌ AI Proxy Error (${tag}) target=${pythonUrl}:`, error.message, error.response?.data || error.code || '');
  return res.status(error.response?.status || 500).json({
    success: false,
    message: error.response?.data?.detail || defaultMsg,
  });
};

// ── Proxy Assistant Message ─────────────────────────────────────
router.post('/assistant/message', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${getPythonUrl()}/assistant/message`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    return handleProxyError('Assistant Message', error, res, 'AI Assistant is currently unavailable.');
  }
});
// ── Proxy Assistant Suggest Reply ────────────────────────────
router.post('/assistant/suggest-reply', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${getPythonUrl()}/assistant/suggest-reply`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    return handleProxyError('Suggest Reply', error, res, 'Failed to generate AI suggestion.');
  }
});

// ── Proxy Assistant Sessions List (ChatGPT History) ──────────────
router.get('/assistant/sessions', async (req: Request, res: Response) => {
  try {
    const { clientId } = req.query;
    const response = await axios.get(`${getPythonUrl()}/assistant/sessions?clientId=${clientId}`);
    return res.json(response.data);
  } catch (error: any) {
    return handleProxyError('Sessions', error, res, 'Failed to fetch chat history.');
  }
});

// ── Proxy Assistant Session Detail ──────────────────────────────
router.get('/assistant/session/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const response = await axios.get(`${getPythonUrl()}/assistant/session/${id}`);
    return res.json(response.data);
  } catch (error: any) {
    return handleProxyError('Session Detail', error, res, 'Failed to load session details.');
  }
});

// ── Proxy Cover Letter Generation ────────────────────────────────
router.post('/cover-letter', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${getPythonUrl()}/ai/cover-letter`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    return handleProxyError('Cover Letter', error, res, 'Cover Letter service is currently unavailable.');
  }
});

// ── Internal: Broadcast AI Message ──────────────────────────────
router.post('/assistant/broadcast-message', async (req: Request, res: Response) => {
  try {
    const { roomId, messageId } = req.body;
    const io = req.app.get('io');

    if (!io) return res.status(500).json({ success: false, message: 'Socket.io not initialized' });

    // Fetch the full message with sender from DB
    const message = await prisma.message.findUnique({
      where: { id: messageId },
      include: {
        sender: { select: { id: true, name: true, profileImage: true, role: true } },
      },
    });

    if (message) {
      // 1. Broadcast to the room
      io.to(roomId).emit('new_message', message);

      // 2. Also notify the specific user (recipient)
      const room = await prisma.chatRoom.findUnique({
        where: { id: roomId },
        include: {
          clientProfile: { select: { userId: true } },
          freelancerProfile: { select: { userId: true } },
        },
      });

      if (room) {
        let recipientId: string | null = null;
        if (room.clientProfile?.userId === message.senderId) {
          recipientId = room.freelancerProfile?.userId || null;
        } else if (room.freelancerProfile?.userId === message.senderId) {
          recipientId = room.clientProfile?.userId || null;
        }

        if (recipientId) {
          io.to(`user:${recipientId}`).emit('new_message', message);
        }
      }

      return res.json({ success: true });
    }

    return res.status(404).json({ success: false, message: 'Message not found' });
  } catch (error: any) {
    console.error('❌ AI Broadcast Error:', error.message);
    return res.status(500).json({ success: false, message: error.message });
  }
});

export const aiRoutes = router;