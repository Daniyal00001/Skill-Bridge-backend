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
import proposalRoutes from './routes/proposal.routes'
import tokenRoutes from './routes/token.routes'
import metadataRoutes from './routes/metadata.routes'
import browseRouter from "./modules/browse/browse.routes";
import trackingRouter from "./routes/tracking.routes";
import contractRoutes from './routes/contract.routes'

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
app.use("/api/browse", browseRouter); // browse project module
app.use("/api/track", trackingRouter); // browse project / tracking module
// proposal routes
app.use('/api/proposals', proposalRoutes)

// token routes (SkillToken economy)
app.use('/api/tokens', tokenRoutes)

// metadata routes (Languages, Locations, etc.)
app.use('/api/metadata', metadataRoutes)

// contract + milestone routes
app.use('/api/contracts', contractRoutes)

export default app