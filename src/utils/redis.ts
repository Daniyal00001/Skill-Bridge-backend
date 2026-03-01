import redis from '../config/redis'

// ── KEY NAMING CONVENTION ─────────────────────────────────────
// WHY: Consistent key names prevent collisions and make
//      debugging easy in Redis CLI
//
// Pattern: category:identifier
// Examples:
//   blacklist:eyJhbGci...    → blacklisted token
//   rate:login:192.168.1.1  → login attempts by IP
//   cache:projects:page:1   → cached projects page 1
//   otp:dani@gmail.com      → email verification OTP

// ─────────────────────────────────────────────────────────────
// 1. TOKEN BLACKLIST
// WHY: When user logs out, their accessToken is still
//      cryptographically valid until it expires (15 min)
//      We blacklist it so it can't be used after logout
// ─────────────────────────────────────────────────────────────

export const blacklistToken = async (
  token: string,
  expirySeconds: number = 15 * 60 // 15 minutes (matches accessToken expiry)
): Promise<void> => {
  await redis.setEx(`blacklist:${token}`, expirySeconds, 'true')
}

export const isTokenBlacklisted = async (token: string): Promise<boolean> => {
  const result = await redis.get(`blacklist:${token}`)
  return result === 'true'
}

// ─────────────────────────────────────────────────────────────
// 2. RATE LIMITING
// WHY: Prevent brute force attacks on login
//      5 failed attempts → block IP for 15 minutes
// ─────────────────────────────────────────────────────────────

export const incrementLoginAttempts = async (ip: string): Promise<number> => {
  const key = `rate:login:${ip}`
  const attempts = await redis.incr(key)

  // Set expiry only on first attempt
  // WHY: If we reset TTL on every attempt, attacker
  //      can keep trying forever by spacing requests
  if (attempts === 1) {
    await redis.expire(key, 15 * 60) // 15 minutes
  }

  return attempts
}

export const getLoginAttempts = async (ip: string): Promise<number> => {
  const result = await redis.get(`rate:login:${ip}`)
  return result ? parseInt(result) : 0
}

export const resetLoginAttempts = async (ip: string): Promise<void> => {
  await redis.del(`rate:login:${ip}`)
}

export const isIPBlocked = async (ip: string): Promise<boolean> => {
  const attempts = await getLoginAttempts(ip)
  return attempts >= 5
}

// ─────────────────────────────────────────────────────────────
// 3. CACHING
// WHY: Frequently read data (project listings, freelancer
//      profiles) doesn't change every second
//      Cache it in Redis → serve instantly → save DB load
// ─────────────────────────────────────────────────────────────

export const setCache = async (
  key: string,
  data: any,
  expirySeconds: number = 5 * 60 // 5 minutes default
): Promise<void> => {
  await redis.setEx(`cache:${key}`, expirySeconds, JSON.stringify(data))
}

export const getCache = async <T>(key: string): Promise<T | null> => {
  const result = await redis.get(`cache:${key}`)
  return result ? JSON.parse(result) : null
}

export const deleteCache = async (key: string): Promise<void> => {
  await redis.del(`cache:${key}`)
}

// Delete all cache keys matching a pattern
// e.g. deletePatternCache('projects:*') clears all project caches
export const deletePatternCache = async (pattern: string): Promise<void> => {
  const keys = await redis.keys(`cache:${pattern}`)
  if (keys.length > 0) {
    await redis.del(keys)
  }
}

// ─────────────────────────────────────────────────────────────
// 4. OTP STORAGE
// WHY: Email verification codes should auto-expire
//      Redis TTL handles this automatically
//      No need for a DB table
// ─────────────────────────────────────────────────────────────

export const storeOTP = async (
  email: string,
  otp: string,
  expirySeconds: number = 10 * 60 // 10 minutes
): Promise<void> => {
  await redis.setEx(`otp:${email}`, expirySeconds, otp)
}

export const getOTP = async (email: string): Promise<string | null> => {
  return redis.get(`otp:${email}`)
}

export const deleteOTP = async (email: string): Promise<void> => {
  await redis.del(`otp:${email}`)
}