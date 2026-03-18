/**
 * role.ts
 * location: backend/src/middlewares/role.ts
 * ─────────────────────────────────────────────────
 * Barrel shim — re-exports `requireRole` from auth.middleware.ts
 * so browse.routes.ts and tracking.routes.ts can import
 * from "../../middlewares/role" without breaking.
 */

export { requireRole } from './auth.middleware'
