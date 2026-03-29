import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function forceBackfill() {
  console.log("🛠️ Force Backfilling lastLoginAt for ALL profiles...");

  try {
    // 1. Clients
    const clients = await prisma.clientProfile.findMany();
    for (const c of clients) {
        await prisma.clientProfile.update({
            where: { id: c.id },
            data: { lastLoginAt: c.createdAt || new Date() }
        });
    }
    console.log(`✅ Updated ${clients.length} Clients.`);

    // 2. Freelancers
    const freelancers = await prisma.freelancerProfile.findMany();
    for (const f of freelancers) {
        await prisma.freelancerProfile.update({
            where: { id: f.id },
            data: { lastLoginAt: f.createdAt || new Date() }
        });
    }
    console.log(`✅ Updated ${freelancers.length} Freelancers.`);

    // 3. Admins
    const admins = await prisma.adminProfile.findMany();
    for (const a of admins) {
        await prisma.adminProfile.update({
            where: { id: a.id },
            data: { lastLoginAt: a.createdAt || new Date() }
        });
    }
    console.log(`✅ Updated ${admins.length} Admins.`);

    console.log("✨ Force Backfill Completed!");
  } catch (error) {
    console.error("❌ Error during backfill:", error);
  } finally {
    await prisma.$disconnect();
  }
}

forceBackfill();
