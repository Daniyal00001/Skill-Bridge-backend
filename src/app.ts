import express from "express";
import dotenv from "dotenv";
import authRoutes from './routes/auth.routes'
import { aiRoutes } from './routes/ai.routes'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import passport from './config/passport'
import { requestLogger } from './middlewares/logger.middleware'

dotenv.config();

const app = express();

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:8080',    // ← frontend is on this port
    'http://localhost:3000',   
  ],
  credentials: true,
}))

app.use(express.json())            // <– required for req.body
app.use(cookieParser())
app.use(requestLogger)
app.use(passport.initialize())  // for google auth
// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth', authRoutes)
app.use('/api/ai', aiRoutes)

export default app

