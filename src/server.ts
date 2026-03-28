import 'dotenv/config'
import http from 'http'
import app from './app'
import { prisma } from './config/prisma'
import './config/redis'
import { initTokenAwardJob } from './jobs/token-award.job'
import { initMilestoneReleaseWorker } from './queues/milestoneRelease.processor'
import { initReviewUnlockWorker } from './queues/reviewUnlock.processor'
import { initChatSocket } from './modules/chat/chat.socket'

const PORT = process.env.PORT || 5000

// Initialize scheduled jobs
initTokenAwardJob()

// Initialize BullMQ workers
initMilestoneReleaseWorker()
initReviewUnlockWorker()

// Create HTTP server and attach socket.io
const httpServer = http.createServer(app)
initChatSocket(httpServer, app)

// Test DB connection on startup
async function startServer() {
  try {
    await prisma.$connect()
    console.log('✅ Database connected')

    httpServer.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`)
      console.log(`🔌 Socket.IO attached`)
    })
  } catch (error) {
    console.error('❌ Database connection failed:', error)
    process.exit(1)
  }
}

startServer()