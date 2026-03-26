import { z } from 'zod'

export const sendMessageSchema = z.object({
  content: z.string().min(1, 'Message content cannot be empty').max(5000),
  type: z.enum(['TEXT', 'FILE', 'SYSTEM']).optional().default('TEXT'),
})

export const openRoomSchema = z.object({
  freelancerProfileId: z.string().min(1),
  clientProfileId: z.string().min(1),
  contractId: z.string().optional(),
  projectId: z.string().optional(),
})

export const muteRoomSchema = z.object({
  muted: z.boolean(),
})

export const restrictUserSchema = z.object({
  targetUserId: z.string().min(1),
  restricted: z.boolean(),
})
