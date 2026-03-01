import 'dotenv/config'
import app from './app'
import { prisma } from './config/prisma'
import './config/redis'

const PORT = process.env.PORT || 5000

// Test DB connection on startup
async function startServer() {
  try {
    await prisma.$connect()
    console.log('✅ Database connected')
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`)
    })
  } catch (error) {
    console.error('❌ Database connection failed:', error)
    process.exit(1)
  }
}

startServer()