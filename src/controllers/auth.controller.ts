import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import { prisma } from '../config/prisma'
import { generateAccessToken, generateRefreshToken } from '../utils/jwt'
import { verifyRefreshToken } from '../utils/jwt'
import {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema
} from '../utils/validators'
import crypto from 'crypto'
import { sendPasswordResetEmail } from '../utils/email'

// ── Redis imports ─────────────────────────────────────────────
import {
  blacklistToken,           // used in: logout
  isIPBlocked,              // used in: login
  incrementLoginAttempts,   // used in: login (on failure)
  resetLoginAttempts,       // used in: login (on success)
} from '../utils/redis'






// ─────────────────────────────────────────────────────────────
// SIGNUP
// Redis used: ❌ not needed
// WHY: New user, no security risk on signup
// ─────────────────────────────────────────────────────────────
export const signup = async (req: Request, res: Response) => {
  console.log("signup called")
  try {
    const parsed = signupSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { name, email, password, role } = parsed.data

    const existingUser = await prisma.user.findUnique({ where: { email } })
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.',
      })
    }

    const hashedPassword = await bcrypt.hash(password, 12)

    const user = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          name,
          email,
          passwordHash: hashedPassword,
          role: role.toUpperCase() as 'CLIENT' | 'FREELANCER',
        },
      })

      if (role === 'client') {
        await tx.clientProfile.create({
          data: { userId: newUser.id, fullName: name },
        })
      } else {
        await tx.freelancerProfile.create({
          data: { userId: newUser.id, fullName: name, languages: [] },
        })
      }

      return newUser
    })

    const accessToken = generateAccessToken({ userId: user.id, role: user.role })
    const refreshToken = generateRefreshToken({ userId: user.id })

    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 7)

    await prisma.session.create({
      data: {
        userId: user.id,
        refreshToken,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        expiresAt,
      },
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    return res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      data: {
        accessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          profileImage: user.profileImage,
          isEmailVerified: user.isEmailVerified,
        },
      },
    })

  } catch (error) {
    console.error('Signup error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again.',
    })
  }
}










// ─────────────────────────────────────────────────────────────
// REFRESH
// Redis used: ❌ not needed
// WHY: Uses httpOnly cookie — already secure
//      DB session check is sufficient here
// ─────────────────────────────────────────────────────────────
export const refresh = async (req: Request, res: Response) => {
  console.log("refresh api called")
  try {
    const token = req.cookies?.refreshToken

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No refresh token found. Please log in.',
      })
    }

    let decoded
    try {
      decoded = verifyRefreshToken(token)
    } catch {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session. Please log in again.',
      })
    }

    const session = await prisma.session.findUnique({
      where: { refreshToken: token },
    })

    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Session not found. Please log in again.',
      })
    }

    if (session.expiresAt < new Date()) {
      await prisma.session.delete({ where: { id: session.id } })
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.',
      })
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        profileImage: true,
        isEmailVerified: true,
        isBanned: true,
      },
    })

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found. Please log in again.',
      })
    }

    if (user.isBanned) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been suspended.',
      })
    }

    const newAccessToken = generateAccessToken({
      userId: user.id,
      role: user.role,
    })

    return res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: newAccessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          profileImage: user.profileImage,
          isEmailVerified: user.isEmailVerified,
        },
      },
    })

  } catch (error) {
    console.error('Refresh error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}







// ─────────────────────────────────────────────────────────────
// LOGIN
// Redis used: ✅ isIPBlocked, incrementLoginAttempts, resetLoginAttempts
// WHY: Prevent brute force — 5 wrong attempts = 15 min block
// ─────────────────────────────────────────────────────────────
export const login = async (req: Request, res: Response) => {
  console.log("login called")
  try {
    const ip = req.ip || 'unknown'

    // ── REDIS: Check if IP is blocked ────────────────────────
    const blocked = await isIPBlocked(ip)
    if (blocked) {
      return res.status(429).json({
        success: false,
        message: 'Too many failed attempts. Please try again in 15 minutes.',
      })
    }

    const parsed = loginSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { email, password } = parsed.data

    const user = await prisma.user.findUnique({ where: { email } })

    if (!user) {
      // ── REDIS: Increment failed attempts ──────────────────
      await incrementLoginAttempts(ip)
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      })
    }

    if (user.isBanned) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been suspended. Contact support.',
      })
    }

    if (!user.passwordHash) {
      return res.status(401).json({
        success: false,
        message: 'This account uses Google login. Please sign in with Google.',
      })
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash)

    if (!isPasswordValid) {
      // ── REDIS: Increment failed attempts ──────────────────
      await incrementLoginAttempts(ip)
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      })
    }

    // ── REDIS: Reset failed attempts on success ───────────────
    await resetLoginAttempts(ip)

    const accessToken = generateAccessToken({ userId: user.id, role: user.role })
    const refreshToken = generateRefreshToken({ userId: user.id })

    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 7)

    await prisma.session.create({
      data: {
        userId: user.id,
        refreshToken,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        expiresAt,
      },
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    return res.status(200).json({
      success: true,
      message: 'Logged in successfully!',
      data: {
        accessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          profileImage: user.profileImage,
          isEmailVerified: user.isEmailVerified,
        },
      },
    })

  } catch (error) {
    console.error('Login error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}








// ─────────────────────────────────────────────────────────────
// LOGOUT
// Redis used: ✅ blacklistToken
// WHY: accessToken is still valid for 15 min after logout
//      Blacklisting it prevents use after logout
//      Middleware (auth.middleware.ts) checks blacklist
// ─────────────────────────────────────────────────────────────
export const logout = async (req: Request, res: Response) => {
  console.log("logout called")
  try {
    // ── REDIS: Blacklist the access token ─────────────────────
    const authHeader = req.headers.authorization
    if (authHeader?.startsWith('Bearer ')) {
      const accessToken = authHeader.split(' ')[1]
      await blacklistToken(accessToken, 15 * 60) // 15 min = accessToken lifetime
    }

    const token = req.cookies?.refreshToken

    if (token) {
      await prisma.session.deleteMany({
        where: { refreshToken: token },
      })
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    })

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    })

  } catch (error) {
    console.error('Logout error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}








// ─────────────────────────────────────────────────────────────
// GOOGLE CALLBACK
// Redis used: ❌ not needed
// WHY: Google handles auth, we just process the result
// ─────────────────────────────────────────────────────────────
export const googleCallback = async (req: Request, res: Response) => {
  console.log("google callback called")
  try {
    const { user, appAccessToken, appRefreshToken } = req.user as any

    res.cookie('refreshToken', appRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8080'

    return res.redirect(
      `${frontendURL}/auth/google/success?token=${appAccessToken}&role=${user.role || ''}`
    )

  } catch (error) {
    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8080'
    return res.redirect(`${frontendURL}/login?error=google_failed`)
  }
}










// ─────────────────────────────────────────────────────────────
// COMPLETE GOOGLE SIGNUP
// Redis used: ❌ not needed
// WHY: One-time action, no security risk
// ─────────────────────────────────────────────────────────────
export const completeGoogleSignup = async (req: Request, res: Response) => {
  try {
    const { role } = req.body
    const userId = req.user?.userId

    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized.' })
    }

    if (!role || !['CLIENT', 'FREELANCER'].includes(role.toUpperCase())) {
      return res.status(400).json({ success: false, message: 'Invalid role selection.' })
    }

    const updatedRole = role.toUpperCase() as 'CLIENT' | 'FREELANCER'

    const user = await prisma.$transaction(async (tx) => {
      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: { role: updatedRole },
      })

      if (updatedRole === 'CLIENT') {
        await tx.clientProfile.create({
          data: { userId: updatedUser.id, fullName: updatedUser.name },
        })
      } else {
        await tx.freelancerProfile.create({
          data: { userId: updatedUser.id, fullName: updatedUser.name, languages: [] },
        })
      }

      return updatedUser
    })

    const accessToken = generateAccessToken({
      userId: user.id,
      role: user.role!,
    })

    return res.status(200).json({
      success: true,
      message: 'Role updated and profile created successfully!',
      data: {
        accessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          profileImage: user.profileImage,
          isEmailVerified: user.isEmailVerified,
        },
      },
    })

  } catch (error) {
    console.error('Complete Google signup error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}










// ─────────────────────────────────────────────────────────────
// FORGOT PASSWORD
// Redis used: ❌ not needed
// WHY: Token stored in DB with expiry is sufficient
//      Could use Redis OTP storage later for speed
// ─────────────────────────────────────────────────────────────
export const forgotPassword = async (req: Request, res: Response) => {
  console.log("forgot password api called")
  try {
    const parsed = forgotPasswordSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid email address.',
      })
    }

    const { email } = parsed.data

    const user = await prisma.user.findUnique({ where: { email } })

    if (!user || !user.passwordHash) {
      return res.status(200).json({
        success: true,
        message: 'If this email exists, a reset link has been sent.',
      })
    }

    await prisma.passwordResetToken.deleteMany({ where: { userId: user.id } })

    const resetToken = crypto.randomBytes(32).toString('hex')
    const expiresAt = new Date()
    expiresAt.setHours(expiresAt.getHours() + 1)

    await prisma.passwordResetToken.create({
      data: { userId: user.id, token: resetToken, expiresAt },
    })

    await sendPasswordResetEmail(user.email, user.name, resetToken)

    return res.status(200).json({
      success: true,
      message: 'If this email exists, a reset link has been sent.',
    })

  } catch (error) {
    console.error('Forgot password error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// RESET PASSWORD
// Redis used: ❌ not needed
// WHY: Token in DB is already secure + single use
// ─────────────────────────────────────────────────────────────
export const resetPassword = async (req: Request, res: Response) => {
  console.log("reset password api called")
  try {
    const parsed = resetPasswordSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { token, password } = parsed.data

    const resetRecord = await prisma.passwordResetToken.findUnique({ where: { token } })

    if (!resetRecord) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset link. Please request a new one.',
      })
    }

    if (resetRecord.expiresAt < new Date()) {
      await prisma.passwordResetToken.delete({ where: { id: resetRecord.id } })
      return res.status(400).json({
        success: false,
        message: 'Reset link has expired. Please request a new one.',
      })
    }

    if (resetRecord.used) {
      return res.status(400).json({
        success: false,
        message: 'Reset link has already been used. Please request a new one.',
      })
    }

    const hashedPassword = await bcrypt.hash(password, 12)

    await prisma.$transaction([
      prisma.user.update({
        where: { id: resetRecord.userId },
        data: { passwordHash: hashedPassword },
      }),
      prisma.passwordResetToken.update({
        where: { id: resetRecord.id },
        data: { used: true },
      }),
      prisma.session.deleteMany({
        where: { userId: resetRecord.userId },
      }),
    ])

    return res.status(200).json({
      success: true,
      message: 'Password reset successfully! Please log in with your new password.',
    })

  } catch (error) {
    console.error('Reset password error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
