import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function checkStats() {
  console.log("📊 Checking current lastLoginAt values in Database...");

  try {
    const clients = await prisma.clientProfile.findMany({
      select: { id: true, userId: true, lastLoginAt: true }
    });
    console.log("Clients:", clients);

    const freelancers = await prisma.freelancerProfile.findMany({
      select: { id: true, userId: true, lastLoginAt: true }
    });
    console.log("Freelancers:", freelancers);

    const logs = await prisma.loginLog.findMany({
      take: 5,
      orderBy: { createdAt: "desc" }
    });
    console.log("Recent Login Logs:", logs);

  } catch (error) {
    console.error("❌ Error checking stats:", error);
  } finally {
    await prisma.$disconnect();
  }
}

checkStats();
