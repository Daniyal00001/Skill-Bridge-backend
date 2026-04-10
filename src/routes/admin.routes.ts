import { Router } from 'express';
import {
  getAdminSkills,
  updateSkillStatus,
  getAdminUserProfile,
  getPendingVerifications,
  getAllVerifications,
  approveVerification,
  rejectVerification,
} from '../controllers/admin.controller';
import {
  getAdminCategories,
  createCategory,
  updateCategory,
  deleteCategory,
  createSubCategory,
  updateSubCategory,
  deleteSubCategory,
} from '../controllers/categoryAdmin.controller';
import {
  getAllUsers,
  banUser,
  getAdminPayments,
  getAdminWithdrawals,
  getAdminLogs,
  getPlatformSettings,
  upsertPlatformSetting,
  grantTokens,
  getAdminAnalytics,
} from '../controllers/adminExtended.controller';
import { protect } from '../middlewares/auth.middleware';

const router = Router();

router.use(protect);

// ── Skills ───────────────────────────────────────────────────
router.get('/skills', getAdminSkills);
router.patch('/skills/:id/status', updateSkillStatus);

// ── User Detail ──────────────────────────────────────────────
router.get('/users/:id/profile', getAdminUserProfile);

// ── User Management ──────────────────────────────────────────
router.get('/users', getAllUsers);
router.patch('/users/:id/ban', banUser);

// ── ID Verifications ─────────────────────────────────────────
router.get('/verifications', getAllVerifications);
router.get('/verifications/pending', getPendingVerifications);
router.post('/verifications/approve/:userId', approveVerification);
router.post('/verifications/reject/:userId', rejectVerification);

// ── Categories ────────────────────────────────────────────────
router.get('/categories', getAdminCategories);
router.post('/categories', createCategory);
router.patch('/categories/:id', updateCategory);
router.delete('/categories/:id', deleteCategory);

// ── Subcategories ─────────────────────────────────────────────
router.post('/categories/:categoryId/subcategories', createSubCategory);
router.patch('/subcategories/:id', updateSubCategory);
router.delete('/subcategories/:id', deleteSubCategory);

// ── Payments & Withdrawals ────────────────────────────────────
router.get('/payments', getAdminPayments);
router.get('/withdrawals', getAdminWithdrawals);

// ── Admin Logs ────────────────────────────────────────────────
router.get('/logs', getAdminLogs);

// ── Platform Settings ─────────────────────────────────────────
router.get('/settings', getPlatformSettings);
router.put('/settings', upsertPlatformSetting);

// ── Token Management ──────────────────────────────────────────
router.post('/tokens/grant', grantTokens);

// ── Analytics ─────────────────────────────────────────────────
router.get('/analytics', getAdminAnalytics);

export default router;
