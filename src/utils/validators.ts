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
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
      'Password must have uppercase, lowercase and a number'
    ),

  role: z.enum(['client', 'freelancer'], {
    errorMap: () => ({ message: 'Role must be client or freelancer' }),
  }),
})

// ── TypeScript type auto-generated from schema ────────────────
export type SignupInput = z.infer<typeof signupSchema>
