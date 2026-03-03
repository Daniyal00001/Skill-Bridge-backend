import { Request, Response, NextFunction } from 'express'
import { verifyAccessToken } from '../utils/jwt'
import { isTokenBlacklisted } from '../utils/redis'

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string
        role: string
      }
    }
  }
}

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.',
      })
    }

    const token = authHeader.split(' ')[1]

    // ── Check blacklist ───────────────────────────────────
    // WHY: User may have logged out but token is still valid
    //      We check Redis blacklist before trusting the token
    const blacklisted = await isTokenBlacklisted(token)
    if (blacklisted) {
      return res.status(401).json({
        success: false,
        message: 'Token has been invalidated. Please log in again.',
      })
    }

    const decoded = verifyAccessToken(token)

    req.user = {
      userId: decoded.userId,
      role: decoded.role,
    }

    next()

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token. Please log in again.',
    })
  }
}

export const requireRole = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated.',
      })
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required: ${roles.join(' or ')}`,
      })
    }

    next()
  }
}