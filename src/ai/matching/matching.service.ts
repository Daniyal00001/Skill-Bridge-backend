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
        if (candidates.length === 0) return { reply: "No freelancers found matching your requirements.", matches: [] }

        // ✅ LLM-based ranking
        const matches = await this.rankingEngine.rankWithLLM(candidates, project)

        // Save with MATCH stage
        await this.sessionService.save({ ...session, matches, stage: AgentStage.MATCH })

        return { reply: this.buildMatchReply(matches, project.projectType ?? null), matches }
    }

    private async queryFreelancers(requiredSkills: string[]): Promise<FreelancerProfile[]> {
        try {
            // Step 1: Exact skill match
            let profiles = await prisma.freelancerProfile.findMany({
                where: {
                    availability: AvailabilityStatus.AVAILABLE,
                    ...(requiredSkills.length > 0 && {
                        skills: { some: { skill: { name: { in: requiredSkills } } } }
                    })
                },
                include: {
                    user: { select: { id: true, name: true } },
                    skills: { include: { skill: { select: { name: true, category: true } } } }
                },
                take: 20
            })

            console.log(`🔍 Exact skill match: ${profiles.length} found`)

            // Step 2: Case insensitive match if no results
            if (profiles.length === 0 && requiredSkills.length > 0) {
                profiles = await prisma.freelancerProfile.findMany({
                    where: {
                        availability: AvailabilityStatus.AVAILABLE,
                        skills: {
                            some: {
                                skill: {
                                    name: { in: requiredSkills, mode: 'insensitive' }
                                }
                            }
                        }
                    },
                    include: {
                        user: { select: { id: true, name: true } },
                        skills: { include: { skill: { select: { name: true, category: true } } } }
                    },
                    take: 20
                })
                console.log(`🔍 Case insensitive match: ${profiles.length} found`)
            }

            // Step 3: Category-based match if still no results
            if (profiles.length === 0 && requiredSkills.length > 0) {
                const categoryMap: Record<string, string> = {
                    'python': 'AI & Machine Learning',
                    'tensorflow': 'AI & Machine Learning',
                    'pytorch': 'AI & Machine Learning',
                    'machine learning': 'AI & Machine Learning',
                    'nlp': 'AI & Machine Learning',
                    'openai': 'AI & Machine Learning',
                    'langchain': 'AI & Machine Learning',
                    'react': 'Web Development',
                    'node': 'Web Development',
                    'nextjs': 'Web Development',
                    'vue': 'Web Development',
                    'angular': 'Web Development',
                    'flutter': 'Mobile Development',
                    'react native': 'Mobile Development',
                    'swift': 'Mobile Development',
                    'kotlin': 'Mobile Development',
                    'figma': 'UI/UX Design',
                    'adobe xd': 'UI/UX Design',
                    'solidity': 'Blockchain & Web3',
                    'ethereum': 'Blockchain & Web3',
                    'aws': 'DevOps & Cloud',
                    'docker': 'DevOps & Cloud',
                    'kubernetes': 'DevOps & Cloud',
                    'unity': 'Game Development',
                    'unreal': 'Game Development',
                }

                const lowerSkills = requiredSkills.map(s => s.toLowerCase())
                let targetCategory = 'Web Development'

                for (const skill of lowerSkills) {
                    for (const [key, cat] of Object.entries(categoryMap)) {
                        if (skill.includes(key) || key.includes(skill)) {
                            targetCategory = cat
                            break
                        }
                    }
                }

                console.log(`🔍 Category fallback: ${targetCategory}`)

                profiles = await prisma.freelancerProfile.findMany({
                    where: {
                        availability: AvailabilityStatus.AVAILABLE,
                        skills: {
                            some: {
                                skill: { category: targetCategory }
                            }
                        }
                    },
                    include: {
                        user: { select: { id: true, name: true } },
                        skills: { include: { skill: { select: { name: true, category: true } } } }
                    },
                    take: 20
                })

                console.log(`🔍 Category match: ${profiles.length} found`)
            }

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