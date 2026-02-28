// for sign up
import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import { prisma } from '../config/prisma'
import { generateAccessToken, generateRefreshToken } from '../utils/jwt'
import { signupSchema  } from '../utils/validators'

// for refresh 
import { verifyRefreshToken } from '../utils/jwt'

// for login
import { loginSchema } from '../utils/validators'



// forgot password
import crypto from 'crypto'
import { sendPasswordResetEmail } from '../utils/email'
import { forgotPasswordSchema, resetPasswordSchema } from '../utils/validators'




// for signup
export const signup = async (req: Request, res: Response) => {
  console.log ("signup called");
  try {

    // ── STEP 1: Validate input ──────────────────────────────
    // validate the input data using zod => validator.ts
    const parsed = signupSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { name, email, password, role } = parsed.data

    // ── STEP 2: Check if email already exists ───────────────
    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.',
      })
    }

    // ── STEP 3: Hash the password ───────────────────────────
    const hashedPassword = await bcrypt.hash(password, 12)

    // ── STEP 4: Create User + Profile in one transaction ────
    //  Transaction     → create User + Profile together
    //                         if one fails, both roll back
    const user = await prisma.$transaction(async (tx) => {

      // Create base user
      const newUser = await tx.user.create({
        data: {
          name,
          email,
          passwordHash: hashedPassword,
          role: role.toUpperCase() as 'CLIENT' | 'FREELANCER',
        },
      })

      // Create role-specific profile
      if (role === 'client') {
        await tx.clientProfile.create({
          data: {
            userId: newUser.id,
            fullName: name,
          },
        })
      } else {
        await tx.freelancerProfile.create({
          data: {
            userId: newUser.id,
            fullName: name,
            languages: [],
          },
        })
      }

      return newUser
    })

    // ── STEP 5: Generate tokens ─────────────────────────────
    const accessToken = generateAccessToken({
      userId: user.id,
      role: user.role,
    })

    const refreshToken = generateRefreshToken({
      userId: user.id,
    })

    // ── STEP 6: Save refresh token in DB ────────────────────
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

    // ── STEP 7: Send refresh token as cookie ────────────────
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
    })

    // ── STEP 8: Send response ───────────────────────────────
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










//  -- -------------------------------------------------------------------

// for refresh 
export const refresh = async (req: Request, res: Response) => {
  console.log ("refresh api called")
  try {

    // ── STEP 1: Get refresh token from cookie ───────────────
    const token = req.cookies?.refreshToken

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No refresh token found. Please log in.',
      })
    }

    // ── STEP 2: Verify the token ────────────────────────────
    let decoded
    try {
      decoded = verifyRefreshToken(token)
    } catch {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session. Please log in again.',
      })
    }

    // ── STEP 3: Check session exists in DB ──────────────────
    // WHY: Token could be valid but already logged out
    //      We store sessions in DB so we can invalidate them
    const session = await prisma.session.findUnique({
      where: { refreshToken: token },
    })

    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Session not found. Please log in again.',
      })
    }

    // ── STEP 4: Check session not expired ───────────────────
    if (session.expiresAt < new Date()) {
      // clean up expired session
      await prisma.session.delete({
        where: { id: session.id },
      })
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.',
      })
    }

    // ── STEP 5: Get user data ────────────────────────────────
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

    // ── STEP 6: Check if user is banned ─────────────────────
    if (user.isBanned) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been suspended.',
      })
    }

    // ── STEP 7: Generate new access token ───────────────────
    // WHY: We only generate a new ACCESS token
    //      Refresh token stays the same until it expires (7 days)
    //      This is called "sliding session" — no need to re-login
    const newAccessToken = generateAccessToken({
      userId: user.id,
      role: user.role,
    })

    // ── STEP 8: Return new access token + user ───────────────
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









// for login
export const login = async (req: Request, res: Response) => {
  console.log("login called")
  try {

    // ── STEP 1: Validate input ──────────────────────────────
    const parsed = loginSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { email, password } = parsed.data

    // ── STEP 2: Find user by email ──────────────────────────
    const user = await prisma.user.findUnique({
      where: { email },
    })

    // ── STEP 3: Check user exists ───────────────────────────
    // WHY: We say "Invalid credentials" for BOTH wrong email
    //      AND wrong password — never tell hackers which is wrong
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      })
    }

    // ── STEP 4: Check user is not banned ────────────────────
    if (user.isBanned) {
      return res.status(403).json({
        success: false,
        message: 'Your account has been suspended. Contact support.',
      })
    }

    // ── STEP 5: Check password exists ───────────────────────
    // WHY: If user signed up with Google, passwordHash is null
    //      They must use Google login instead
    if (!user.passwordHash) {
      return res.status(401).json({
        success: false,
        message: 'This account uses Google login. Please sign in with Google.',
      })
    }

    // ── STEP 6: Verify password ─────────────────────────────
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash)

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials.',
      })
    }

    // ── STEP 7: Generate tokens ─────────────────────────────
    const accessToken = generateAccessToken({
      userId: user.id,
      role: user.role,
    })

    const refreshToken = generateRefreshToken({
      userId: user.id,
    })

    // ── STEP 8: Save new session in DB ──────────────────────
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

    // ── STEP 9: Set refresh token as httpOnly cookie ─────────
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    // ── STEP 10: Send response ──────────────────────────────
    // WHY: We return role from DB — frontend uses this
    //      to redirect to correct dashboard automatically
    return res.status(200).json({
      success: true,
      message: 'Logged in successfully!',
      data: {
        accessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,        // ← from DB, not from request
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












// logout

export const logout = async (req: Request, res: Response) => {
  console.log("logout called")
  try {

    // ── STEP 1: Get refresh token from cookie ───────────────
    const token = req.cookies?.refreshToken

    if (!token) {
      return res.status(200).json({
        success: true,
        message: 'Logged out successfully.',
      })
    }

    // ── STEP 2: Delete session from DB ──────────────────────
    // WHY: This invalidates the refresh token permanently
    //      Even if someone stole it, it no longer works
    await prisma.session.deleteMany({
      where: { refreshToken: token },
    })

    // ── STEP 3: Clear the cookie ────────────────────────────
    // WHY: Must send same options as when we SET the cookie
    //      Otherwise browser won't clear it
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









// google auth 
// ── Google OAuth callback ─────────────────────────────────────
// This runs after Google redirects back to our app
export const googleCallback = async (req: Request, res: Response) => {
  console.log("google callback called")
  try {
    // Passport attaches the result to req.user
    const { user, appAccessToken, appRefreshToken } = req.user as any

    // Set refresh token cookie
    res.cookie('refreshToken', appRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    // Redirect to frontend with accessToken in URL
    // WHY URL param: we can't set headers on a redirect
    // Frontend reads it once then stores in memory
    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8080'

    return res.redirect(
      `${frontendURL}/auth/google/success?token=${appAccessToken}&role=${user.role || ''}`
    )

  } catch (error) {
    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8080'
    return res.redirect(`${frontendURL}/login?error=google_failed`)
  }
}

// ── Complete Google Signup ────────────────────────────────────
// Update role and create profile for new Google users
export const completeGoogleSignup = async (req: Request, res: Response) => {
  try {
    const { role } = req.body
    const userId = req.user?.userId

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized.',
      })
    }

    if (!role || !['CLIENT', 'FREELANCER'].includes(role.toUpperCase())) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role selection.',
      })
    }

    const updatedRole = role.toUpperCase() as 'CLIENT' | 'FREELANCER'

    const user = await prisma.$transaction(async (tx) => {
      // 1. Update user role
      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: { role: updatedRole },
      })

      // 2. Create profile
      if (updatedRole === 'CLIENT') {
        await tx.clientProfile.create({
          data: {
            userId: updatedUser.id,
            fullName: updatedUser.name,
          },
        })
      } else {
        await tx.freelancerProfile.create({
          data: {
            userId: updatedUser.id,
            fullName: updatedUser.name,
            languages: [],
          },
        })
      }

      return updatedUser
    })

    // 3. Generate new access token with the role
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
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}







// ── Forgot Password ───────────────────────────────────────────
export const forgotPassword = async (req: Request, res: Response) => {
  console.log("forgot password api called")
  try {

    // ── STEP 1: Validate email ──────────────────────────────
    const parsed = forgotPasswordSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid email address.',
      })
    }

    const { email } = parsed.data

    // ── STEP 2: Find user ───────────────────────────────────
    const user = await prisma.user.findUnique({
      where: { email },
    })

    // ── STEP 3: Always return success ──────────────────────
    // WHY: Never reveal if email exists or not
    //      Hackers use this to enumerate valid emails
    //      We send the same response regardless
    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If this email exists, a reset link has been sent.',
      })
    }

    // ── STEP 4: Check if user uses Google login ─────────────
    if (!user.passwordHash) {
      return res.status(200).json({
        success: true,
        message: 'If this email exists, a reset link has been sent.',
      })
    }

    // ── STEP 5: Delete any existing reset tokens ────────────
    // WHY: User should only have one valid reset token at a time
    await prisma.passwordResetToken.deleteMany({
      where: { userId: user.id },
    })

    // ── STEP 6: Generate secure reset token ─────────────────
    // WHY: crypto.randomBytes is cryptographically secure
    //      Never use Math.random() for security tokens
    const resetToken = crypto.randomBytes(32).toString('hex')

    const expiresAt = new Date()
    expiresAt.setHours(expiresAt.getHours() + 1) // 1 hour

    await prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        token: resetToken,
        expiresAt,
      },
    })

    // ── STEP 7: Send email ──────────────────────────────────
    await sendPasswordResetEmail(user.email, user.name, resetToken)

    return res.status(200).json({
      success: true,
      message: 'If this email exists, a reset link has been sent.',
    })

  } catch (error) {
    console.error('Forgot password error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}











// ── Reset Password ────────────────────────────────────────────
export const resetPassword = async (req: Request, res: Response) => {
  console.log("reset password api called")
  try {

    // ── STEP 1: Validate input ──────────────────────────────
    const parsed = resetPasswordSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { token, password } = parsed.data

    // ── STEP 2: Find the reset token ────────────────────────
    const resetRecord = await prisma.passwordResetToken.findUnique({
      where: { token },
    })

    // ── STEP 3: Validate token ──────────────────────────────
    if (!resetRecord) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset link. Please request a new one.',
      })
    }

    // ── STEP 4: Check token not expired ────────────────────
    if (resetRecord.expiresAt < new Date()) {
      await prisma.passwordResetToken.delete({
        where: { id: resetRecord.id },
      })
      return res.status(400).json({
        success: false,
        message: 'Reset link has expired. Please request a new one.',
      })
    }

    // ── STEP 5: Check token not already used ────────────────
    if (resetRecord.used) {
      return res.status(400).json({
        success: false,
        message: 'Reset link has already been used. Please request a new one.',
      })
    }

    // ── STEP 6: Hash new password ───────────────────────────
    const hashedPassword = await bcrypt.hash(password, 12)

    // ── STEP 7: Update password + mark token as used ────────
    // WHY transaction: both must succeed together
    await prisma.$transaction([
      prisma.user.update({
        where: { id: resetRecord.userId },
        data: { passwordHash: hashedPassword },
      }),
      prisma.passwordResetToken.update({
        where: { id: resetRecord.id },
        data: { used: true },
      }),
      // Delete all sessions — force re-login everywhere
      // WHY: If someone stole their old password,
      //      changing password logs them out everywhere
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
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    })
  }
}