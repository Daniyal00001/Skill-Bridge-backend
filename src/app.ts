import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRoutes from './routes/auth.routes'

const app = express()

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:8080',    // ← frontend is on this port
    'http://localhost:3000',   
  ],
  credentials: true,
}))

app.use(express.json())
app.use(cookieParser())

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth', authRoutes)

// ── Health check ──────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send('SkillBridge API Running 🚀')
})

export default app