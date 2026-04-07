import { Router } from 'express';
import { getAdminSkills, updateSkillStatus, getAdminUserProfile } from '../controllers/admin.controller';
import { protect } from '../middlewares/auth.middleware';

const router = Router();

router.use(protect);

router.get('/skills', getAdminSkills);
router.patch('/skills/:id/status', updateSkillStatus);
router.get('/users/:id/profile', getAdminUserProfile);

export default router;
