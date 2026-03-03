import { z } from 'zod'

// ── Signup Schema ─────────────────────────────────────────────
export const signupSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name too long')
    .trim(),

  email: z
    .string()
    .email('Please enter a valid email')
    .toLowerCase()
    .trim(),

  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
      'Password must have uppercase, lowercase, a number and a special character (@$!%*?&)'
    ),

  role: z.enum(['client', 'freelancer'], {
    errorMap: () => ({ message: 'Role must be client or freelancer' }),
  }),
})




// ── Login Schema ──────────────────────────────────────────────
export const loginSchema = z.object({
  email: z
    .string()
    .email('Please enter a valid email')
    .toLowerCase()
    .trim(),

  password: z
    .string()
    .min(1, 'Password is required'),
})



// ── Forgot Password Schema ────────────────────────────────────
export const forgotPasswordSchema = z.object({
  email: z
    .string()
    .email('Please enter a valid email')
    .toLowerCase()
    .trim(),
})

// ── Reset Password Schema ─────────────────────────────────────
export const resetPasswordSchema = z.object({
  token: z
    .string()
    .min(1, 'Reset token is required'),

  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
      'Password must have uppercase, lowercase, a number and a special character (@$!%*?&)'
    ),
})


export type LoginInput = z.infer<typeof loginSchema>
export type SignupInput = z.infer<typeof signupSchema>
