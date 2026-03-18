import { PrismaClient, AvailabilityStatus } from '@prisma/client'
import { RankingEngine } from './ranking.engine'
import { SessionService } from '../memory/session.service'
import { AgentSession, FreelancerProfile, MatchedFreelancer } from '../shared/agent.types'
import { AgentStage } from '../shared/constants'

const prisma = new PrismaClient()

export class MatchingService {
    private rankingEngine = new RankingEngine()
    private sessionService = new SessionService()

    async handle(session: AgentSession): Promise<{ reply: string; matches: MatchedFreelancer[] }> {
        const project = session.project
        if (!project) return { reply: 'I need project details first.', matches: [] }

        const candidates = await this.queryFreelancers(project.techPreferences ?? [])
        if (candidates.length === 0) return { reply: "No freelancers found.", matches: [] }

        const matches = this.rankingEngine.rank(candidates, project)

        // ✅ Save with MATCH stage (not OUTREACH)
        await this.sessionService.save({ ...session, matches, stage: AgentStage.MATCH })

        return { reply: this.buildMatchReply(matches, project.projectType ?? null), matches }
    }

    private async queryFreelancers(requiredSkills: string[]): Promise<FreelancerProfile[]> {
        try {
            const profiles = await prisma.freelancerProfile.findMany({
                where: {
                    availability: AvailabilityStatus.AVAILABLE,
                    ...(requiredSkills.length > 0 && {
                        skills: { some: { skill: { name: { in: requiredSkills } } } }
                    })
                },
                include: {
                    user: { select: { id: true, name: true } },
                    skills: { include: { skill: { select: { name: true } } } }
                },
                take: 20
            })

            return profiles.map(p => ({
                id: p.userId,
                name: p.fullName,
                location: p.location ?? '',
                skills: p.skills.map(s => s.skill.name),
                rating: 0,
                hourlyRate: p.hourlyRate ?? 0,
                completedProjects: 0,
                bio: p.bio ?? '',
                availability: p.availability === AvailabilityStatus.AVAILABLE,
                specializations: [],
            }))
        } catch (error: any) {
            console.error('❌ Prisma error:', error.message)
            return []
        }
    }

    private buildMatchReply(matches: MatchedFreelancer[], projectType: string | null): string {
        const names = matches.slice(0, 3)
            .map((m, i) => `${i + 1}. **${m.name}** — Score: ${m.matchScore}/100 · ${m.matchReason}`)
            .join('\n')
        return `Found ${matches.length} freelancers for your ${projectType || 'project'}!\n\n${names}\n\nClick "Hire" on any freelancer to start negotiation!`
    }
}