import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function fix() {
  const result = await prisma.user.updateMany({
    where: { idVerificationStatus: { not: "APPROVED" } },
    data: { isIdVerified: false }
  });
  console.log(`Updated ${result.count} users.`);
}
fix().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1) });
