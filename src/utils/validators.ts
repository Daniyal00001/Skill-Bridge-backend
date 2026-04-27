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

// ── Project Schema ────────────────────────────────────────────
export const createProjectSchema = z.object({
  title: z.string().min(5, 'Title must be at least 5 characters').max(80, 'Title too long').trim(),
  shortDesc: z.string().min(10).max(120).trim().optional(),
  description: z.string().min(30, 'Description must be at least 30 characters').max(10000).trim(),
  requirements: z.string().max(10000).optional(),
  budget: z.number({ invalid_type_error: 'Budget must be a number' }).positive('Budget must be positive').max(1_000_000, 'Budget exceeds maximum'),
  budgetType: z.enum(['fixed', 'hourly', 'FIXED', 'HOURLY']).optional(),
  deadline: z.coerce.date().refine(d => d > new Date(), { message: 'Deadline must be in the future' }),
  skills: z.array(z.string().min(1).max(50)).max(15, 'Too many skills').optional(),
  experienceLevel: z.string().optional(),
  hiringMethod: z.string().optional(),
  categoryId: z.string().min(1, 'Category is required'),
  subCategoryId: z.string().optional(),
  languageId: z.string().optional(),
  locationId: z.string().optional(),
  referenceLinks: z.string().max(500).optional(),
})

// ── Proposal Schema ───────────────────────────────────────────
export const submitProposalSchema = z.object({
  bidAmount: z.number({ invalid_type_error: 'Bid amount must be a number' }).positive('Bid amount must be positive').max(1_000_000),
  deliveryDays: z.number({ invalid_type_error: 'Delivery days must be a number' }).int().positive().max(365, 'Delivery cannot exceed 365 days'),
  coverLetter: z.string().min(50, 'Cover letter must be at least 50 characters').max(15000, 'Cover letter too long'),
  generalRevisionLimit: z.number().int().min(-1).max(100).optional(),
})

// ── Review Schema ─────────────────────────────────────────────
export const createReviewSchema = z.object({
  rating: z.number({ invalid_type_error: 'Rating must be a number' }).min(1).max(5),
  comment: z.string().min(10, 'Review must be at least 10 characters').max(2000, 'Review too long').trim(),
})

// ── Milestone Schema (for contract) ──────────────────────────
export const milestoneItemSchema = z.object({
  title: z.string().min(2, 'Milestone title required').max(100).trim(),
  description: z.string().max(1000).optional(),
  amount: z.number({ invalid_type_error: 'Amount must be a number' }).positive().max(1_000_000),
  dueDate: z.coerce.date().optional(),
  allowedRevisions: z.number().int().min(-1).max(100).optional(),
})

export const setMilestonesSchema = z.object({
  milestones: z.array(milestoneItemSchema).min(1, 'At least one milestone required').max(20, 'Too many milestones'),
})

// ── Dispute Schema ────────────────────────────────────────────
export const createDisputeSchema = z.object({
  projectId: z.string().min(1, 'Project ID is required'),
  disputeType: z.enum(['PAYMENT', 'QUALITY', 'DELIVERY', 'COMMUNICATION', 'OTHER']),
  reason: z.string().min(10, 'Reason must be at least 10 characters').max(500).trim(),
  details: z.string().max(3000).optional(),
})

// ── Onboarding Schemas ────────────────────────────────────────

export const onboardingStep1Schema = z.object({
  fullName: z.string().min(3, 'Full name must be at least 3 characters').max(50, 'Full name too long').trim(),
  phoneNumber: z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format. Must start with "+".'),
  location: z.string().min(1, 'Country is required'),
  region: z.string().optional(),
  tagline: z.string().min(10, 'Tagline must be at least 10 characters').max(100, 'Tagline too long').trim(),
})

export const onboardingStep2Schema = z.object({
  hourlyRate: z.number({ invalid_type_error: 'Hourly rate must be a number' }).min(5, 'Minimum hourly rate is $5'),
  bio: z.string().min(100, 'Bio must be at least 100 characters').max(5000, 'Bio too long').trim(),
  availability: z.enum(['AVAILABLE', 'BUSY', 'UNAVAILABLE', 'PART_TIME', 'FULL_TIME']),
  experienceLevel: z.enum(['ENTRY', 'INTERMEDIATE', 'EXPERT']),
  preferredBudgetMin: z.number().nonnegative().optional().nullable(),
  preferredBudgetMax: z.number().nonnegative().optional().nullable(),
})

export const onboardingStep3Schema = z.object({
  skills: z.array(z.object({
    name: z.string().min(1).max(50),
    level: z.number().min(1).max(5).optional()
  })).min(1, 'At least one skill is required'),
  education: z.array(z.object({
    school: z.string().min(1).max(100),
    degree: z.string().min(1).max(100),
    year: z.string().regex(/^\d{4}$/, 'Invalid year format')
  })).optional(),
  certifications: z.array(z.object({
    title: z.string().min(1).max(100),
    issuingOrganization: z.string().min(1).max(100),
    issueDate: z.coerce.date(),
    expiryDate: z.coerce.date().optional(),
    credentialUrl: z.string().url().optional().or(z.literal(''))
  })).optional(),
  languages: z.array(z.string()).optional(),
  gigs: z.array(z.object({
    title: z.string().min(1).max(100),
    description: z.string().max(500).optional(),
    fileUrl: z.string().url().optional()
  })).optional()
})

export const onboardingStep5Schema = z.object({
  github: z.string().url('Invalid GitHub URL').optional().or(z.literal('')),
  linkedin: z.string().url('Invalid LinkedIn URL').optional().or(z.literal('')),
  portfolio: z.string().url('Invalid Portfolio URL').optional().or(z.literal('')),
  website: z.string().url('Invalid Website URL').optional().or(z.literal('')),
  preferredCategories: z.array(z.string()).max(4, 'Maximum 4 categories allowed').optional()
})

// ── Invitation Schema ─────────────────────────────────────────
export const inviteFreelancerSchema = z.object({
  projectId: z.string().min(1, 'Project ID is required'),
  message: z.string().min(20, 'Message must be at least 20 characters').max(2000, 'Message too long').trim(),
  budget: z.number().positive().optional().nullable(),
  revisionsAllowed: z.number().int().min(0).max(100).optional(),
  milestones: z.array(milestoneItemSchema).optional().nullable(),
})

// ── Stripe Schemas ───────────────────────────────────────────
export const stripePaymentIntentSchema = z.object({
  contractId: z.string().min(1, 'Contract ID is required'),
  milestoneId: z.string().min(1, 'Milestone ID is required'),
})

export const stripeConfirmFundSchema = z.object({
  contractId: z.string().min(1, 'Contract ID is required'),
  milestoneId: z.string().min(1, 'Milestone ID is required'),
  paymentIntentId: z.string().min(1, 'Payment Intent ID is required'),
})

export const purchaseTokensSchema = z.object({
  tokenAmount: z.number().int().positive('Token amount must be a positive integer').max(1000, 'Maximum 1000 tokens per purchase'),
  paymentMethodId: z.string().min(1, 'Payment method ID is required'),
})

export const requestWithdrawalSchema = z.object({
  amount: z.number().positive('Withdrawal amount must be positive').min(25, 'Minimum withdrawal amount is $25.00').max(10000, 'Maximum $10,000 per withdrawal'),
})

// ── Token Purchase Schemas ────────────────────────────────────
export const buyTokensWithBalanceSchema = z.object({
  amountOfMoney: z.number().positive('Amount must be positive').min(1, 'Minimum purchase is $1.00'),
})

export const createTokenIntentSchema = z.object({
  amountOfMoney: z.number().positive('Amount must be positive').min(1, 'Minimum purchase is $1.00'),
})

export const confirmTokenPurchaseSchema = z.object({
  paymentIntentId: z.string().min(1, 'Payment Intent ID is required'),
})
