import { Router } from 'express';
import { protect, requireRole } from '../middlewares/auth.middleware';
import {
  getAllDisputes,
  getDisputeById,
  updateDisputeStatus,
  resolveDispute,
  updateDisputeSummary,
  createDispute,
  getMyDispute,
  addDisputeNote,
} from '../controllers/dispute.controller';

const router = Router();

// All routes require authentication
router.use(protect);

// ── User routes (Client / Freelancer) ─────────────────────────
// Create a new dispute
router.post('/', createDispute);

// Get dispute for a specific project (the caller must be a party)
router.get('/my/:projectId', getMyDispute);

// ── Admin routes ──────────────────────────────────────────────
// List all disputes with filters + stats
router.get('/', requireRole('ADMIN'), getAllDisputes);

// Get single dispute detail
router.get('/:id', requireRole('ADMIN'), getDisputeById);

// Update status (e.g., UNDER_REVIEW, RESOLVED, CLOSED)
router.patch('/:id/status', requireRole('ADMIN'), updateDisputeStatus);

// Resolve a dispute (FAVOR_CLIENT, FAVOR_FREELANCER, etc.)
router.patch('/:id/summary', requireRole('ADMIN'), updateDisputeSummary);
router.patch('/:id/resolve', requireRole('ADMIN'), resolveDispute);

// Add internal mediation note
router.post('/:id/note', requireRole('ADMIN'), addDisputeNote);

export default router;
