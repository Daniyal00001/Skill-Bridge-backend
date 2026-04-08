import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function syncDisputedContracts() {
  console.log('--- Starting Dispute Status Sync ---');

  // Find all projects that are in DISPUTED status
  const disputedProjects = await prisma.project.findMany({
    where: { status: 'DISPUTED' },
  });

  console.log(`Found ${disputedProjects.length} projects in DISPUTED status.`);

  let updatedCount = 0;
  for (const project of disputedProjects) {
    const result = await prisma.contract.updateMany({
      where: {
        projectId: project.id,
        status: { not: 'DISPUTED' }, // Only update if not already set
      },
      data: { status: 'DISPUTED' },
    });
    updatedCount += result.count;
  }

  console.log(`Successfully synchronized ${updatedCount} contracts to DISPUTED status.`);
  console.log('--- Sync Complete ---');
}

syncDisputedContracts()
  .catch((e) => {
    console.error('Error during sync:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
