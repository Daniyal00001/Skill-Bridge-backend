import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('--- Migrating WAITING_FOR_RESPONSE disputes to UNDER_REVIEW ---');
  
  const count = await prisma.dispute.count({
    where: { status: 'WAITING_FOR_RESPONSE' as any }
  });
  
  if (count === 0) {
    console.log('No WAITING_FOR_RESPONSE disputes found. Skipping migration.');
    return;
  }
  
  const result = await prisma.dispute.updateMany({
    where: { status: 'WAITING_FOR_RESPONSE' as any },
    data: { status: 'UNDER_REVIEW' }
  });
  
  console.log(`Successfully migrated ${result.count} disputes.`);
}

main()
  .catch((e) => {
    console.error('Migration failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
