/**
 * cleanOrphanedFreelancers.ts
 *
 * Removes FreelancerProfile documents whose userId references a
 * User document that no longer exists in the database.
 *
 * Run with:
 *   npx ts-node --project tsconfig.json prisma/cleanOrphanedFreelancers.ts
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  console.log("🔍 Scanning for orphaned FreelancerProfile records...\n");

  // 1. Fetch every FreelancerProfile (only id + userId)
  const allProfiles = await prisma.freelancerProfile.findMany({
    select: { id: true, userId: true, fullName: true },
  });

  console.log(`   Total FreelancerProfile records found: ${allProfiles.length}`);

  // 2. For each profile, check whether the linked user exists
  const orphaned: { id: string; userId: string; fullName: string }[] = [];

  for (const profile of allProfiles) {
    const userExists = await prisma.user.findUnique({
      where: { id: profile.userId },
      select: { id: true },
    });

    if (!userExists) {
      orphaned.push(profile);
    }
  }

  if (orphaned.length === 0) {
    console.log("\n✅ No orphaned FreelancerProfile records found. Database is clean!");
    return;
  }

  console.log(`\n⚠️  Found ${orphaned.length} orphaned profile(s):`);
  for (const o of orphaned) {
    console.log(`   • Profile ID: ${o.id} | userId: ${o.userId} | name: ${o.fullName}`);
  }

  // 3. Delete orphaned profiles (Prisma cascade will clean up child records)
  const orphanedIds = orphaned.map((o) => o.id);

  const deleted = await prisma.freelancerProfile.deleteMany({
    where: { id: { in: orphanedIds } },
  });

  console.log(`\n🗑️  Deleted ${deleted.count} orphaned FreelancerProfile record(s).`);
  console.log("✅ Cleanup complete!");
}

main()
  .catch((err) => {
    console.error("❌ Cleanup script failed:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
