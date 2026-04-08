import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function run() {
  const users = await prisma.user.findMany({
    where: { isIdVerified: true },
    select: { id: true, email: true, idVerificationStatus: true, isIdVerified: true }
  });

  console.log("Total verified users in DB:", users.length);
  
  for (const user of users) {
    if (user.idVerificationStatus !== 'APPROVED') {
       console.log(`Fixing ${user.email} (Status: ${user.idVerificationStatus})`);
       await prisma.user.update({
         where: { id: user.id },
         data: { isIdVerified: false }
       });
    }
  }
}
run().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1) });
