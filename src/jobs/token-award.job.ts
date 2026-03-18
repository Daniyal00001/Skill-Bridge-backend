import cron from 'node-cron'
import { awardMonthlyTokens } from '../services/token.service'

/**
 * Schedules the token award job to run on the 1st of every month at 00:00 (midnight).
 */
export const initTokenAwardJob = () => {
  console.log('🕒 Initializing Monthly Token Award Job (Schedule: 1st of every month at midnight)')
  
  // Cron expression for the 1st day of every month at 00:00:00
  // Seconds Minutes Hours DayOfMonth Month DayOfWeek
  cron.schedule('0 0 0 1 * *', async () => {
    console.log('🚀 Running monthly token award job...')
    await awardMonthlyTokens()
  })
}
