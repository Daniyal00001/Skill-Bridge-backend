import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRoutes from './routes/auth.routes'
import passport from './config/passport'
import { requestLogger } from './middlewares/logger.middleware'
import projectRoutes from './routes/project.routes'
import categoryRoutes from "./routes/category.routes";
import freelancerRoutes from './routes/freelancer.routes'
import proposalRoutes from './routes/proposal.routes'

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
app.use(requestLogger)
app.use(passport.initialize())  // for google auth


// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth', authRoutes)


// to fetch categories and sub categories
app.use("/api/categories", categoryRoutes);


// project routes 
app.use('/api/projects', projectRoutes)

// freelancer routes
app.use('/api/freelancers', freelancerRoutes)

// proposal routes
app.use('/api/proposals', proposalRoutes)



export default app