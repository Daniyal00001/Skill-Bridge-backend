import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function deepCleanAndSync() {
  console.log("🚀 Starting Deep Data Integrity Check & Sync...");

  try {
    // 1. Delete orphaned Proposals (no FreelancerProfile)
    const proposals = await prisma.proposal.findMany({
      select: { id: true, freelancerProfileId: true },
    });
    const profileIds = (await prisma.freelancerProfile.findMany({ select: { id: true } })).map(p => p.id);
    const orphanedProposals = proposals.filter(p => p.freelancerProfileId && !profileIds.includes(p.freelancerProfileId));
    
    if (orphanedProposals.length > 0) {
      console.log(`🧹 Deleting ${orphanedProposals.length} orphaned Proposals...`);
      await prisma.proposal.deleteMany({
        where: { id: { in: orphanedProposals.map(p => p.id) } },
      });
    }

    // 2. Delete orphaned Invitations (no FreelancerProfile)
    const invitations = await prisma.invitation.findMany({
      select: { id: true, freelancerProfileId: true },
    });
    const orphanedInvitations = invitations.filter(i => i.freelancerProfileId && !profileIds.includes(i.freelancerProfileId));
    
    if (orphanedInvitations.length > 0) {
      console.log(`🧹 Deleting ${orphanedInvitations.length} orphaned Invitations...`);
      await prisma.invitation.deleteMany({
        where: { id: { in: orphanedInvitations.map(i => i.id) } },
      });
    }

    // 3. Delete orphaned FreelancerProfiles (no User)
    const profiles = await prisma.freelancerProfile.findMany({
      select: { id: true, userId: true },
    });
    const userIds = (await prisma.user.findMany({ select: { id: true } })).map(u => u.id);
    const orphanedProfiles = profiles.filter(p => !userIds.includes(p.userId));

    if (orphanedProfiles.length > 0) {
      console.log(`🧹 Deleting ${orphanedProfiles.length} orphaned FreelancerProfiles...`);
      await prisma.freelancerProfile.deleteMany({
        where: { id: { in: orphanedProfiles.map(p => p.id) } },
      });
    }

    // 4. SYNC: Update profileCompletionScore to match profileCompletion
    console.log("🔄 Syncing profileCompletionScore for all freelancers...");
    const allFreelancers = await prisma.freelancerProfile.findMany({
      select: { id: true, profileCompletion: true }
    });

    for (const f of allFreelancers) {
      await prisma.freelancerProfile.update({
        where: { id: f.id },
        data: { profileCompletionScore: f.profileCompletion }
      });
    }
    console.log(`✅ Synced ${allFreelancers.length} profiles.`);

    console.log("✨ Deep Clean & Sync Completed Successfully!");
  } catch (error) {
    console.error("❌ Error during deep clean:", error);
  } finally {
    await prisma.$disconnect();
  }
}

deepCleanAndSync();
