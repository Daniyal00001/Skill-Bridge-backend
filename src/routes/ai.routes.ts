import { Router, Request, Response } from 'express';
import axios from 'axios';

const router = Router();
const PYTHON_AI_URL = process.env.PYTHON_AI_URL || 'http://localhost:8000/api';

// ── Proxy Assistant Message ─────────────────────────────────────
router.post('/assistant', async (req: Request, res: Response) => {
  try {
    const response = await axios.post(`${PYTHON_AI_URL}/assistant/message`, req.body);
    return res.json(response.data);
  } catch (error: any) {
    console.error('❌ AI Proxy Error (Assistant):', error.message);
    return res.status(error.response?.status || 500).json({ 
      success: false, 
      message: error.response?.data?.detail || 'AI Assistant is currently unavailable.' 
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