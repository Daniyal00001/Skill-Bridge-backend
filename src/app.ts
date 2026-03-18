import express from "express";
import dotenv from "dotenv";
import authRoutes from './routes/auth.routes'
import { aiRoutes } from './routes/ai.routes'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import passport from './config/passport'
import { requestLogger } from './middlewares/logger.middleware'
import projectRoutes from './routes/project.routes'
import categoryRoutes from "./routes/category.routes";
import freelancerRoutes from './routes/freelancer.routes'

dotenv.config();

const app = express();

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:8080',
    'http://localhost:3000',
  ],
  credentials: true,
}))

app.use(express.json())
app.use(cookieParser())
app.use(requestLogger)
app.use(passport.initialize())

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth', authRoutes)
app.use('/api/ai', aiRoutes)
app.use('/api/projects', projectRoutes)
app.use('/api/categories', categoryRoutes)
app.use('/api/freelancers', freelancerRoutes)

export default app