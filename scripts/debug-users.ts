import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function debugUsers() {
  try {
    const users = await prisma.user.findMany({ take: 5 });
    console.log("Users in DB:", JSON.stringify(users, null, 2));

    const logs = await prisma.loginLog.findMany({ take: 5 });
    console.log("LoginLogs in DB:", JSON.stringify(logs, null, 2));
  } catch (error) {
    console.error("Debug failed:", error);
  } finally {
    await prisma.$disconnect();
  }
}

debugUsers();
