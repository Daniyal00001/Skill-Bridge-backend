import { prisma } from './config/prisma';
import { updateClientStats } from './services/tracking.service';

async function verify() {
  const allContracts = await prisma.contract.findMany({
    include: { project: { select: { clientProfileId: true } } }
  });

  console.log('Total contracts in DB:', allContracts.length);
  if (allContracts.length > 0) {
    console.log('First contract:', {
      id: allContracts[0].id,
      projectId: allContracts[0].projectId,
      clientId: allContracts[0].project?.clientProfileId
    });
  }

  const client = await prisma.clientProfile.findFirst({
    select: { id: true, fullName: true, totalHires: true, hireRate: true }
  });

  if (!client) {
    console.log('No client found');
    return;
  }

  console.log('Before update for client', client.fullName, ':', client);

  // Manual check for contracts for this client
  const manualCount = await prisma.contract.count({
    where: { project: { clientProfileId: client.id } }
  });
  console.log('Manual contract count for this client:', manualCount);

  await updateClientStats(prisma as any, client.id);

  const updatedClient = await prisma.clientProfile.findUnique({
    where: { id: client.id },
    select: { id: true, fullName: true, totalHires: true, hireRate: true }
  });

  console.log('After update:', updatedClient);
  process.exit(0);
}

verify().catch(err => {
  console.error(err);
  process.exit(1);
});
