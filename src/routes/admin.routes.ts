import { Router } from 'express';
import { getAdminSkills, updateSkillStatus, getAdminUserProfile, getPendingVerifications, getAllVerifications, approveVerification, rejectVerification } from '../controllers/admin.controller';
import { protect } from '../middlewares/auth.middleware';

const router = Router();

router.use(protect);

router.get('/skills', getAdminSkills);
router.patch('/skills/:id/status', updateSkillStatus);
router.get('/users/:id/profile', getAdminUserProfile);

router.get('/verifications', getAllVerifications);
router.get('/verifications/pending', getPendingVerifications);
router.post('/verifications/approve/:userId', approveVerification);
router.post('/verifications/reject/:userId', rejectVerification);

export default router;
