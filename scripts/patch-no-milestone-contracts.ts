/**
 * One-time patch: adds a "Full Project Deliverable" milestone to any
 * existing ACTIVE contract that has zero milestones.
 *
 * Run with: npx tsx scripts/patch-no-milestone-contracts.ts
 */
import 'dotenv/config'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  // Find all contracts with no milestones
  const contracts = await prisma.contract.findMany({
    where: {
      status: { in: ['ACTIVE', 'OFFER_PENDING'] },
      milestones: { none: {} }, // zero milestones
    },
    include: {
      milestones: true,
      project: { select: { title: true } },
    },
  })

  if (contracts.length === 0) {
    console.log('✅ No contracts without milestones found.')
    return
  }

  console.log(`🔧 Found ${contracts.length} contract(s) with no milestones. Patching...`)

  for (const contract of contracts) {
    await prisma.milestone.create({
      data: {
        contractId: contract.id,
        order: 0,
        title: 'Full Project Deliverable',
        description:
          'Complete the project as described in the proposal and deliver all agreed-upon work.',
        amount: contract.agreedPrice,
        status: 'PENDING',
        allowedRevisions: 3,
        attachments: [],
      },
    })
    console.log(`  ✅ Patched contract ${contract.id} (${contract.project.title}) — added default milestone of $${contract.agreedPrice}`)
  }

  console.log('🎉 Done!')
}

main()
  .catch((e) => { console.error(e); process.exit(1) })
  .finally(() => prisma.$disconnect())
