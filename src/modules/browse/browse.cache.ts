/**
 * browse.cache.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY SEPARATE FILE: Cache logic is infrastructure concern.
 * Keeping it separate means we can swap Redis for Memcached or even
 * in-memory Map() for local dev without touching browse.service.ts
 *
 * TTL = 60 seconds by default.
 * WHY 60s: At ~100 freelancers, cache provides ~100x DB call reduction.
 * Short TTL means personalization stays fresh (new project = appears
 * in feed within 60s without any manual invalidation needed).
 * ─────────────────────────────────────────────────────────────────
 */

import redis from "../../config/redis";
import { BrowseResponse } from "./browse.types";

export async function getCachedFeed(
  key: string
): Promise<BrowseResponse | null> {
  try {
    const raw = await redis.get(key);
    if (!raw) return null;
    return JSON.parse(raw) as BrowseResponse;
  } catch (err) {
    // Cache miss is acceptable — degrade gracefully, don't crash
    console.warn("[BrowseCache] Redis GET failed, skipping cache:", err);
    return null;
  }
}

export async function setCachedFeed(
  key: string,
  response: BrowseResponse,
  ttlSeconds: number
): Promise<void> {
  try {
    await redis.setEx(key, ttlSeconds, JSON.stringify(response));
  } catch (err) {
    // Cache write failure is non-fatal — user still gets response from DB
    console.warn("[BrowseCache] Redis SET failed:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// MANUAL INVALIDATION
// Called when a new project is posted or a project status changes.
// We can't know every freelancer's cache key, so we use Redis SCAN
// to find and delete all browse:v1:* keys.
// WHY not just wait for TTL? Because a client just posted a project
// and wants freelancers to see it NOW — 60s delay matters here.
// ─────────────────────────────────────────────────────────────────
export async function invalidateBrowseCache(
  freelancerId?: string
): Promise<void> {
  try {
    const pattern = freelancerId
      ? `browse:v1:${freelancerId}:*`
      : "browse:v1:*";

    // SCAN is non-blocking unlike KEYS — safe for production
    const keys: string[] = [];
    for await (const key of redis.scanIterator({ MATCH: pattern, COUNT: 100 })) {
      keys.push(key);
    }

    if (keys.length > 0) {
      await (redis as any).del(keys);
      console.log(`[BrowseCache] Invalidated ${keys.length} cache keys`);
    }
  } catch (err) {
    console.warn("[BrowseCache] Invalidation failed:", err);
  }
}