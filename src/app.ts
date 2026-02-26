// import express from 'express'
// import cors from 'cors'
// import cookieParser from 'cookie-parser'
// import dotenv from 'dotenv'

// // import routes
// import authRoutes from './routes/auth.routes'

// dotenv.config()

// const app = express()

// // Middleware
// app.use(cors({
//   origin: process.env.FRONTEND_URL || 'http://localhost:5173',
//   credentials: true,
// }))

// app.use(express.json())
// app.use(cookieParser())


// // Routes 
// // /api/auth/signup
// app.use('/api/auth', authRoutes)

// export default app


import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRoutes from './routes/auth.routes'

const app = express()

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:8080',    // ← your frontend is on this port
    'http://localhost:3000',    // ← just in case
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