import { prisma } from '../config/prisma'
import { TokenWalletTxType, TokenTxReason } from '@prisma/client'

/**
 * Awards 10 tokens to all freelancer profiles and records the transaction.
 */
export const awardMonthlyTokens = async () => {
  try {
    console.log('🔄 Starting monthly token award process...')
    
    // Find all freelancer profiles
    const freelancers = await prisma.freelancerProfile.findMany({
      select: { id: true, skillTokenBalance: true }
    })

    if (freelancers.length === 0) {
      console.log('ℹ️ No freelancers found to award tokens.')
      return
    }

    const awardAmount = 10
    
    // Process in a transaction for reliability
    const result = await prisma.$transaction(async (tx) => {
      let count = 0
      for (const freelancer of freelancers) {
        const newBalance = freelancer.skillTokenBalance + awardAmount
        
        // Update balance
        await tx.freelancerProfile.update({
          where: { id: freelancer.id },
          data: { skillTokenBalance: newBalance }
        })

        // Create transaction record
        await tx.tokenTransaction.create({
          data: {
            freelancerProfileId: freelancer.id,
            type: TokenWalletTxType.CREDIT,
            reason: TokenTxReason.MONTHLY_AWARD,
            amount: awardAmount,
            balanceAfter: newBalance,
            description: `Monthly gift! +${awardAmount} SkillTokens awarded.`
          }
        })
        count++
      }
      return count
    })

    console.log(`✅ Successfully awarded ${awardAmount} tokens to ${result} freelancers.`)
  } catch (error) {
    console.error('❌ Error awarding monthly tokens:', error)
  }
}
