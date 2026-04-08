import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function run() {
  const usersToFix = await prisma.user.findMany({
    where: {
      isIdVerified: true,
      idVerificationStatus: { not: "APPROVED" }
    },
    select: { id: true, email: true, idVerificationStatus: true }
  });

  console.log("Found users to fix:", usersToFix.length);
  
  for (const user of usersToFix) {
    await prisma.user.update({
      where: { id: user.id },
      data: { isIdVerified: false }
    });
    console.log(`Fixed: ${user.email}`);
  }
}
run().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1) });
