import { createClient } from 'redis'

// ── Create Redis client ───────────────────────────────────────
const client = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
})

// ── Handle connection events ──────────────────────────────────
client.on('connect', () => {
  console.log('✅ Redis connected')
})

client.on('error', (error) => {
  console.error('❌ Redis error:', error)
})

client.on('reconnecting', () => {
  console.log('🔄 Redis reconnecting...')
})

// ── Connect ───────────────────────────────────────────────────
client.connect()

export default client