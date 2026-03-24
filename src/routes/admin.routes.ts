import { Router } from 'express';
import { getAdminSkills, updateSkillStatus } from '../controllers/admin.controller';
import { protect } from '../middlewares/auth.middleware';

const router = Router();

router.use(protect);

router.get('/skills', getAdminSkills);
router.patch('/skills/:id/status', updateSkillStatus);

export default router;
