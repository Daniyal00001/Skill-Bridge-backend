import { Request, Response, NextFunction } from 'express';
import { checkContentModeration } from '../utils/moderation';

export const contentFilterMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const content = req.body?.content;
  const userId = (req as any).user?.userId;

  if (!content || !userId) return next();

  const modResult = await checkContentModeration(userId, content);

  if (modResult.hasViolation) {
    return res.status(403).json({
      message: modResult.message,
      violationType: modResult.violationType,
      isBlocked: modResult.isAccountBlocked
    });
  }

  next();
};
