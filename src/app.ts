import express from "express";
import helmet from "helmet";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes";
import { aiRoutes } from "./routes/ai.routes";
import cors from "cors";
import cookieParser from "cookie-parser";
import passport from "./config/passport";
import { requestLogger } from "./middlewares/logger.middleware";
import projectRoutes from "./routes/project.routes";
import categoryRoutes from "./routes/category.routes";
import freelancerRoutes from "./routes/freelancer.routes";
import proposalRoutes from "./routes/proposal.routes";
import tokenRoutes from "./routes/token.routes";
import metadataRoutes from "./routes/metadata.routes";
import browseProjectsRouter from "./modules/browse-projects/browse-projects.routes";
import trackingRouter from "./routes/tracking.routes";
import contractRoutes from "./routes/contract.routes";
import adminRoutes from "./routes/admin.routes";
import dashboardRoutes from "./routes/dashboard.routes";
import browseFreelancersRouter from "./modules/browse-freelancers/browseFreelancers.routes";

dotenv.config();

const app = express();

// ── Middlewares ───────────────────────────────────────────────
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:8080",
      "http://localhost:3000",
    ],
    credentials: true,
  }),
);

app.use(express.json());
app.use(cookieParser());
app.use(requestLogger);
app.use(passport.initialize());

// ── Routes ────────────────────────────────────────────────────
app.use("/api/auth", authRoutes);
app.use("/api/ai", aiRoutes);
app.use("/api/projects", projectRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/freelancers", freelancerRoutes);
app.use("/api/browse-projects", browseProjectsRouter); // browse project module
app.use("/api/track", trackingRouter); // browse project / tracking module
// proposal routes
app.use("/api/proposals", proposalRoutes);

// token routes (SkillToken economy)
app.use("/api/tokens", tokenRoutes);

// metadata routes (Languages, Locations, etc.)
app.use("/api/metadata", metadataRoutes);

// contract + milestone routes
app.use("/api/contracts", contractRoutes);

// client routes
import clientRoutes from "./routes/client.routes";
app.use("/api/client", clientRoutes);

// invitation routes
import invitationRoutes from "./routes/invitation.routes";
app.use("/api/invitations", invitationRoutes);

// notification routes
import notificationRoutes from "./routes/notification.routes";
app.use("/api/notifications", notificationRoutes);

// review routes
import reviewRoutes from "./routes/review.routes";
app.use("/api/reviews", reviewRoutes);

// dispute routes
import disputeRoutes from "./routes/dispute.routes";
app.use("/api/disputes", disputeRoutes);

// admin routes
app.use("/api/admin", adminRoutes);

// dashboard aggregation routes
app.use("/api/dashboard", dashboardRoutes);

// chat module routes (REST) — now with Socket.IO too
import chatRoutes from "./modules/chat/chat.routes";
app.use("/api/chat", chatRoutes);

app.use("/api/browse", browseFreelancersRouter);

export default app;
