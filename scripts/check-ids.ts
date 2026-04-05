import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function check() {
  const projectId = '69d2a51766b65f1fc7966613';
  const contractId = '69d2a5ee66b65f1fc796661b';
  const milestoneId = '69d2a5ee66b65f1fc796661c';

  console.log('--- Checking Project ---');
  const project = await prisma.project.findUnique({ where: { id: projectId } });
  console.log('Project:', project ? 'Exists' : 'NOT FOUND');

  console.log('--- Checking Dispute ---');
  const dispute = await prisma.dispute.findFirst({ where: { projectId } });
  console.log('Dispute:', dispute ? 'Exists' : 'NOT FOUND');

  console.log('--- Checking Contract ---');
  const contract = await prisma.contract.findUnique({ where: { id: contractId } });
  console.log('Contract:', contract ? 'Exists' : 'NOT FOUND');

  console.log('--- Checking Milestone ---');
  const milestone = await prisma.milestone.findUnique({ where: { id: milestoneId } });
  console.log('Milestone:', milestone ? 'Exists' : 'NOT FOUND');

  await prisma.$disconnect();
}

check();
