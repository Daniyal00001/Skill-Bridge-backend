import { Router, Request, Response } from 'express';
import axios from 'axios';

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

export const aiRoutes = router;