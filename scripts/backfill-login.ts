import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function backfillLastLogin() {
  console.log("🛠️ Backfilling lastLoginAt for all profiles...");

  try {
    // 1. Clients
    const clients = await prisma.clientProfile.findMany({ where: { lastLoginAt: null } });
    for (const c of clients) {
        await prisma.clientProfile.update({
            where: { id: c.id },
            data: { lastLoginAt: c.createdAt || new Date() }
        });
    }
    console.log(`✅ Backfilled ${clients.length} Clients.`);

    // 2. Freelancers
    const freelancers = await prisma.freelancerProfile.findMany({ where: { lastLoginAt: null } });
    for (const f of freelancers) {
        await prisma.freelancerProfile.update({
            where: { id: f.id },
            data: { lastLoginAt: f.createdAt || new Date() }
        });
    }
    console.log(`✅ Backfilled ${freelancers.length} Freelancers.`);

    // 3. Admins
    const admins = await prisma.adminProfile.findMany({ where: { lastLoginAt: null } });
    for (const a of admins) {
        await prisma.adminProfile.update({
            where: { id: a.id },
            data: { lastLoginAt: a.createdAt || new Date() }
        });
    }
    console.log(`✅ Backfilled ${admins.length} Admins.`);

    console.log("✨ Backfill Completed!");
  } catch (error) {
    console.error("❌ Error during backfill:", error);
  } finally {
    await prisma.$disconnect();
  }
}

backfillLastLogin();
