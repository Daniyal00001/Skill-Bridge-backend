import { Router } from 'express';
import { handleAssistantMessage } from '../ai/assistant.controller'; // ← fix path

const router = Router();

router.post('/assistant', handleAssistantMessage);

export const aiRoutes = router; // Make sure you export this