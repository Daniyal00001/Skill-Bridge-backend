import { prisma } from '../config/prisma';
import axios from 'axios';

export const patterns = {
  phone: /(\+92|0092|0)?[-.\s]?3[0-9]{2}[-.\s]?[0-9]{7}|(\+1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/gi,
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
  whatsapp: /whatsapp|watsapp|wa\.me|whats.?app/gi,
  social: /instagram|facebook|twitter|linkedin|snapchat|tiktok|@[a-zA-Z0-9_]+/gi,
  cnic: /\d{5}-\d{7}-\d{1}/g,
};

export interface ModerationResult {
  hasViolation: boolean;
  violationType?: string;
  isAccountBlocked: boolean;
  message: string | null;
  sanitizedMessage?: string | null;
}

const AI_BACKEND_URL = process.env.AI_BACKEND_URL || 'http://localhost:8000';

export async function checkContentModeration(
  userId: string,
  content: string,
  roomId?: string
): Promise<ModerationResult> {
  let hasViolation = false;
  let violationType = '';

  // 1. Quick Pattern Match (fast local check before hitting AI)
  for (const [key, pattern] of Object.entries(patterns)) {
    // Reset lastIndex for global regexes before re-testing
    pattern.lastIndex = 0;
    if (pattern.test(content)) {
      hasViolation = true;
      violationType = key;
      break;
    }
  }

  // 2. Fetch User Data
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { violationCount: true, isBanned: true }
  });

  if (user?.isBanned) {
    return { 
      hasViolation: true, 
      isAccountBlocked: true, 
      message: "🚫 Your account is banned due to policy violations." 
    };
  }

  // 3. AI Moderation Check (Deep analysis via Python BlockingService)
  //    If roomId is provided, use the full blocking flow which persists
  //    violations and injects system messages into the chat room.
  //    Otherwise, fall back to the lightweight /moderate endpoint.
  if (!hasViolation) {
    try {
      if (roomId) {
        // Full blocking pipeline — handles warn/block + DB logging
        const aiResponse = await axios.post(`${AI_BACKEND_URL}/api/assistant/moderate/check`, {
          message: content,
          senderId: userId,
          roomId: roomId,
          contractStatus: "NONE",
        }, { timeout: 15000 });

        const result = aiResponse.data;

        if (result.action === 'block') {
          return {
            hasViolation: true,
            violationType: 'policy_violation',
            isAccountBlocked: true,
            message: result.message,
          };
        }

        if (result.action === 'warn') {
          return {
            hasViolation: true,
            violationType: result.severity || 'policy_violation',
            isAccountBlocked: false,
            message: result.message,
            sanitizedMessage: result.sanitizedMessage,
          };
        }

        // action === 'allow' — no violation detected by AI
      } else {
        // Lightweight check (no room context — e.g. AI Assistant chat)
        const aiResponse = await axios.post(`${AI_BACKEND_URL}/api/assistant/moderate`, {
          message: content,
          violationCount: user?.violationCount || 0
        }, { timeout: 15000 });

        const aiResult = aiResponse.data.result;
        if (aiResult?.violation) {
          hasViolation = true;
          violationType = aiResult.detected_patterns?.[0] || 'policy_violation';
        }
      }
    } catch (err) {
      console.error("AI Moderation call failed, falling back to pattern matching only.");
    }
  }

  if (!hasViolation) {
    return { hasViolation: false, isAccountBlocked: false, message: null };
  }

  // 4. Update violation count and handle Ban (Prisma side)
  const newCount = (user?.violationCount || 0) + 1;
  const isBanned = newCount >= 2;

  await prisma.user.update({
    where: { id: userId },
    data: {
      violationCount: newCount,
      lastViolationAt: new Date(),
      isBanned: isBanned,
      isFlagged: true,
      banReason: isBanned ? "Automated ban: Multiple policy violations (Sharing contact info/Off-platform deals)" : undefined
    }
  });

  if (!isBanned) {
    return {
      hasViolation: true,
      violationType,
      isAccountBlocked: false,
      message: "⚠️ Sharing personal contact information or discussing off-platform deals is strictly prohibited. This is your first warning. Next violation will result in a permanent ban."
    };
  } else {
    return {
      hasViolation: true,
      violationType,
      isAccountBlocked: true,
      message: "🚫 Second violation detected. Your account has been permanently banned for violating platform safety policies."
    };
  }
}
