import { Router } from 'express';
import { protect, requireRole } from '../middlewares/auth.middleware';
import {
  getAdminDashboard,
  getClientDashboard,
  getFreelancerDashboard
} from '../controllers/dashboard.controller';

const router = Router();

// Secure all dashboard routes intrinsically
router.use(protect);

/**
 * @route   GET /api/dashboard/admin
 * @desc    Get admin dashboard aggregated data
 * @access  Private (ADMIN)
 */
router.get('/admin', requireRole('ADMIN'), getAdminDashboard);

/**
 * @route   GET /api/dashboard/client
 * @desc    Get client dashboard aggregated data
 * @access  Private (CLIENT)
 */
router.get('/client', requireRole('CLIENT'), getClientDashboard);

/**
 * @route   GET /api/dashboard/freelancer
 * @desc    Get freelancer dashboard aggregated data
 * @access  Private (FREELANCER)
 */
router.get('/freelancer', requireRole('FREELANCER'), getFreelancerDashboard);

export default router;
