import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRoutes from './routes/auth.routes'
import passport from './config/passport'

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
app.use(passport.initialize())  // for google auth
// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth', authRoutes)



export default app