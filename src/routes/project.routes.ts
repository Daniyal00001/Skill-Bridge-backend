import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { upload } from '../middlewares/upload.middleware'
import {
  createProject,
  updateProject,
  getAllProjects,
  getMyProjects,
  getProjectById,
  deleteProject
} from '../controllers/project.controller'

const router = Router()

router.post('/', protect, requireRole('CLIENT'), upload.array('files', 5), createProject)
router.patch('/:id', protect, requireRole('CLIENT'), updateProject)
router.get('/client/my', protect, requireRole('CLIENT'), getMyProjects)
router.get('/', protect, getAllProjects)
router.get('/:id', protect, getProjectById)
router.delete('/:id', protect, requireRole('CLIENT'), deleteProject)

export default router