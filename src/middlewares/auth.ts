/**
 * auth.ts
 * location: backend/src/middlewares/auth.ts
 * ─────────────────────────────────────────────────
 * Barrel shim — re-exports `protect` as `requireAuth`
 * so browse.routes.ts and tracking.routes.ts can import
 * from "../../middlewares/auth" without breaking.
 */

export { protect as requireAuth } from './auth.middleware'
