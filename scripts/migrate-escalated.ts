import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('--- Migrating ESCALATED disputes to UNDER_REVIEW ---');
  
  const count = await prisma.dispute.count({
    where: { status: 'ESCALATED' as any }
  });
  
  if (count === 0) {
    console.log('No ESCALATED disputes found. Skipping migration.');
    return;
  }
  
  const result = await prisma.dispute.updateMany({
    where: { status: 'ESCALATED' as any },
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
