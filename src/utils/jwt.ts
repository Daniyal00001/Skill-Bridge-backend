import jwt from 'jsonwebtoken'

// ── Types — what data we store INSIDE each token ─────────────
export interface AccessTokenPayload {
  userId: string
  role: string
}

export interface RefreshTokenPayload {
  userId: string
}

// ── Generate Access Token ─────────────────────────────────────
export const generateAccessToken = (payload: AccessTokenPayload): string => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: '15m',  // expires in 15 minutes
  })
}

// ── Generate Refresh Token ────────────────────────────────────
export const generateRefreshToken = (payload: RefreshTokenPayload): string => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: '7d',   // expires in 7 days
  })
}

// ── Verify Access Token ───────────────────────────────────────
export const verifyAccessToken = (token: string): AccessTokenPayload => {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as AccessTokenPayload
}

// ── Verify Refresh Token ──────────────────────────────────────
export const verifyRefreshToken = (token: string): RefreshTokenPayload => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as RefreshTokenPayload
}