import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function verifyFix() {
  console.log("Verifying fix by simulating dashboard queries...");

  try {
    // 1. Check for invitations with missing freelancers
    const invitations = await prisma.invitation.findMany({
      include: {
        freelancerProfile: {
          include: { user: { select: { name: true } } }
        }
      }
    });
    console.log(`Successfully fetched ${invitations.length} invitations.`);

    // 2. Check for proposals with missing freelancers
    const proposals = await prisma.proposal.findMany({
      include: {
        freelancerProfile: {
          include: { user: { select: { name: true } } }
        }
      }
    });
    console.log(`Successfully fetched ${proposals.length} proposals.`);

    console.log("Verification successful! All records have their required relations.");
  } catch (error) {
    console.error("Verification failed:", error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

verifyFix();
