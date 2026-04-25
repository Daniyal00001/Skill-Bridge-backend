import { Router, Request, Response } from 'express';
import axios from 'axios';
import { prisma } from '../config/prisma';

const router = Router();
const PYTHON_AI_URL = process.env.PYTHON_AI_URL || 'http://localhost:8000/api';

// ── Proxy Assistant Message ─────────────────────────────────────
router.post('/assistant/message', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${PYTHON_AI_URL}/assistant/message`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Assistant Message):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: error.response?.data?.detail || 'AI Assistant is currently unavailable.' 
    });
  }
});
// ── Proxy Assistant Suggest Reply ────────────────────────────
router.post('/assistant/suggest-reply', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${PYTHON_AI_URL}/assistant/suggest-reply`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Suggest Reply):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: 'Failed to generate AI suggestion.' 
    });
  }
});

// ── Proxy Assistant Sessions List (ChatGPT History) ──────────────
router.get('/assistant/sessions', async (req: Request, res: Response) => {
  try {
    const { clientId } = req.query;
    const response = await axios.get(`${PYTHON_AI_URL}/assistant/sessions?clientId=${clientId}`);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Sessions):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: 'Failed to fetch chat history.' 
    });
  }
});

// ── Proxy Assistant Session Detail ──────────────────────────────
router.get('/assistant/session/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const response = await axios.get(`${PYTHON_AI_URL}/assistant/session/${id}`);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Session Detail):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: 'Failed to load session details.' 
    });
  }
});

// ── Proxy Cover Letter Generation ────────────────────────────────
router.post('/cover-letter', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${PYTHON_AI_URL}/ai/cover-letter`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Cover Letter):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: error.response?.data?.detail || 'Cover Letter service is currently unavailable.' 
    });
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