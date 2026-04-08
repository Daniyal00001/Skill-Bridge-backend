import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function run() {
  const users = await prisma.user.findMany({
    where: { isIdVerified: true },
    select: { email: true, idVerificationStatus: true, isIdVerified: true }
  });
  console.log("Verified users:", JSON.stringify(users, null, 2));
}
run().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1) });
