import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
prisma.user.findFirst({ where: { email: "skillbridgeofficial.pk@gmail.com" } }).then(u => {
  console.log("isIdVerified:", u?.isIdVerified, "status:", u?.idVerificationStatus);
  process.exit(0);
});
