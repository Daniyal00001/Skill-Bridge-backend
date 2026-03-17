import { prisma } from '../config/prisma'
import { updateProfileCompletion } from './profileCompletion'

async function recalibrate() {
  const allProfiles = await prisma.freelancerProfile.findMany()
  
  for (const p of allProfiles) {
    const score = await updateProfileCompletion(p.userId)
    console.log(`User ${p.userId} is now ${score}% complete.`)
  }
}

recalibrate()
  .then(() => process.exit(0))
  .catch(console.error)
