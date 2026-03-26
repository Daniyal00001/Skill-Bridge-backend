import rateLimit from "express-rate-limit";

export const messageRateLimiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 20, // Limit each IP to 20 requests per `window` (here, per 10 seconds)
  message: {
    status: 429,
    message: "Too many messages sent from this IP, please try again after 10 seconds",
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // For production behind a proxy (like Nginx), you might need:
  // keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
});
