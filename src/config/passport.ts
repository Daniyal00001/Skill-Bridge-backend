import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { prisma } from './prisma'
import { generateAccessToken, generateRefreshToken } from '../utils/jwt'

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value
        const name = profile.displayName
        const googleId = profile.id
        const profileImage = profile.photos?.[0]?.value

        if (!email) {
          return done(new Error('No email from Google'), undefined)
        }

        // ── Check if user already exists ──────────────────
        let user = await prisma.user.findFirst({
          where: {
            OR: [
              { googleId },
              { email },
            ],
          },
        })

        if (user) {
          // ── Existing user — update googleId if missing ──
          if (!user.googleId) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: { googleId, profileImage: user.profileImage || profileImage },
            })
          }
        } else {
          // ── New user — create account + profile ─────────
          // WHY transaction: user + profile must both succeed
          user = await prisma.$transaction(async (tx) => {
            const newUser = await tx.user.create({
              data: {
                name,
                email,
                googleId,
                profileImage,
                // passwordHash is null — Google users have no password
                role: null, // No default role for Google signup
                isEmailVerified: true, // Google already verified the email
              },
            })

            return newUser
          })
        }

        // ── Generate our own tokens ───────────────────────
        const appAccessToken = generateAccessToken({
          userId: user.id,
          role: user.role,
        })

        const appRefreshToken = generateRefreshToken({
          userId: user.id,
        })

        // ── Save session ──────────────────────────────────
        const expiresAt = new Date()
        expiresAt.setDate(expiresAt.getDate() + 7)

        await prisma.session.create({
          data: {
            userId: user.id,
            refreshToken: appRefreshToken,
            expiresAt,
          },
        })

        // ── Pass tokens to callback ───────────────────────
        return done(null, {
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            profileImage: user.profileImage,
            isEmailVerified: user.isEmailVerified,
          },
          appAccessToken,
          appRefreshToken,
        })

      } catch (error) {
        return done(error, undefined)
      }
    }
  )
)

export default passport