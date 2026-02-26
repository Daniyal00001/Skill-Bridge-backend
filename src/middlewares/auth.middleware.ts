import { Request, Response, NextFunction } from 'express'
import { verifyAccessToken } from '../utils/jwt'

// ── Extend Express Request type ───────────────────────────────
// WHY: By default req.user doesn't exist in Express
//      We add it so controllers can access req.user.userId etc.
// just for typescript....extra safety
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

// ── protect ───────────────────────────────────────────────────
// Use this on any route that requires login
// Example: router.get('/profile', protect, getProfile)
export const protect = (req: Request, res: Response, next: NextFunction) => {
  try {
    // Token comes in header like:
    // Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.',
      })
    }

    // Remove "Bearer " and get just the token
    const token = authHeader.split(' ')[1]

    // Verify — throws error if invalid or expired
    const decoded = verifyAccessToken(token)

    // Attach user info to request
    // Now any controller after this can use req.user
    req.user = {
      userId: decoded.userId,
      role: decoded.role,
    }

    next() // move to next middleware or controller

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token. Please log in again.',
    })
  }
}

// ── requireRole ───────────────────────────────────────────────
// Use AFTER protect to restrict to specific roles
// Example: router.get('/admin', protect, requireRole('ADMIN'), ...)
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
