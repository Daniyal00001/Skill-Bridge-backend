import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/prisma';

const patterns = {
  phone: /(\+92|0092|0)?[-.\s]?3[0-9]{2}[-.\s]?[0-9]{7}|(\+1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/gi,
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
  whatsapp: /whatsapp|watsapp|wa\.me|whats.?app/gi,
  social: /instagram|facebook|twitter|linkedin|snapchat|tiktok|@[a-zA-Z0-9_]+/gi,
  cnic: /\d{5}-\d{7}-\d{1}/g,
};

export const contentFilterMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const { content } = req.body;
  const userId = (req as any).user?.id; // Assuming user is attached by authMiddleware

  if (!content || !userId) return next();

  let hasViolation = false;
  for (const [key, pattern] of Object.entries(patterns)) {
    if (pattern.test(content)) {
      hasViolation = true;
      break;
    }
  }

  if (hasViolation) {
    try {
      // Fetch user to check current violation count
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { violationCount: true }
      });

      const newCount = (user?.violationCount || 0) + 1;

      // Update violation stats
      await prisma.user.update({
        where: { id: userId },
        data: {
          violationCount: newCount,
          lastViolationAt: new Date(),
          isFlagged: newCount >= 2
        }
      });

      if (newCount === 1) {
        return res.status(403).json({
          message: "⚠️ Sharing personal contact information is not allowed on SkillBridge. This protects both parties. Your message was not sent."
        });
      } else {
        return res.status(403).json({
          message: "🚫 Second violation detected. Your account has been flagged for review."
        });
      }
    } catch (error) {
      console.error('[ContentFilter] Error updating violations:', error);
      // Even if update fails, we still block the message
      return res.status(403).json({
        message: "⚠️ Sharing personal contact information is not allowed on SkillBridge."
      });
    }
  }

  next();
};
