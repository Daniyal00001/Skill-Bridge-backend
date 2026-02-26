import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import { prisma } from '../config/prisma'
import { generateAccessToken, generateRefreshToken } from '../utils/jwt'
import { signupSchema } from '../utils/validators'

export const signup = async (req: Request, res: Response) => {
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
